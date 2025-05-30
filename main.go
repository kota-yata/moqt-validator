package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Error types
var (
	ErrProtocolViolation = errors.New("protocol violation")
	ErrValidation        = errors.New("validation error")
)

// Session termination codes
const (
	NoError                  = 0x0
	InternalError            = 0x1
	Unauthorized             = 0x2
	ProtocolViolation        = 0x3
	InvalidRequestID         = 0x4
	DuplicateTrackAlias      = 0x5
	KeyValueFormattingError  = 0x6
	TooManyRequests          = 0x7
	InvalidPath              = 0x8
	MalformedPath            = 0x9
	GoawayTimeout            = 0x10
	ControlMessageTimeout    = 0x11
	DataStreamTimeout        = 0x12
	AuthTokenCacheOverflow   = 0x13
	DuplicateAuthTokenAlias  = 0x14
	VersionNegotiationFailed = 0x15
)

// Message Types
const (
	// Reserved for older versions
	ReservedSetup          = 0x01
	ReservedClientSetupOld = 0x40
	ReservedServerSetupOld = 0x41

	// Current setup messages
	ClientSetup = 0x20
	ServerSetup = 0x21

	// Control messages
	Goaway          = 0x10
	MaxRequestID    = 0x15
	RequestsBlocked = 0x1A

	// Subscribe messages
	Subscribe       = 0x3
	SubscribeOK     = 0x4
	SubscribeError  = 0x5
	Unsubscribe     = 0xA
	SubscribeUpdate = 0x2
	SubscribeDone   = 0xB

	// Fetch messages
	Fetch       = 0x16
	FetchOK     = 0x18
	FetchError  = 0x19
	FetchCancel = 0x17

	// Track status messages
	TrackStatusRequest = 0xD
	TrackStatus        = 0xE

	// Announce messages
	Announce       = 0x6
	AnnounceOK     = 0x7
	AnnounceError  = 0x8
	Unannounce     = 0x9
	AnnounceCancel = 0xC

	// Subscribe announces messages
	SubscribeAnnounces      = 0x11
	SubscribeAnnouncesOK    = 0x12
	SubscribeAnnouncesError = 0x13
	UnsubscribeAnnounces    = 0x14
)

// Filter Types
const (
	NextGroupStart = 0x1
	LatestObject   = 0x2
	AbsoluteStart  = 0x3
	AbsoluteRange  = 0x4
)

// Group Order
const (
	GroupOrderDefault    = 0x0
	GroupOrderAscending  = 0x1
	GroupOrderDescending = 0x2
)

// Object Status
const (
	ObjectStatusNormal       = 0x0
	ObjectStatusDoesNotExist = 0x1
	ObjectStatusEndOfGroup   = 0x3
	ObjectStatusEndOfTrack   = 0x4
)

// Stream Types
const (
	SubgroupHeaderBase = 0x08
	FetchHeader        = 0x05
)

// Datagram Types
const (
	ObjectDatagramNoExt   = 0x00
	ObjectDatagramWithExt = 0x01
	ObjectStatusNoExt     = 0x02
	ObjectStatusWithExt   = 0x03
)

// Parameter Types
const (
	// Setup parameters
	SetupParamPath                  = 0x01
	SetupParamMaxRequestID          = 0x02
	SetupParamMaxAuthTokenCacheSize = 0x04

	// Version parameters
	VersionParamAuthorizationToken = 0x01
	VersionParamDeliveryTimeout    = 0x02
	VersionParamMaxCacheDuration   = 0x04
)

// Extension Header Types
const (
	ExtHeaderPriorGroupIDGap = 0x40
)

// Alias Types for Authorization Token
const (
	AliasTypeDelete   = 0x0
	AliasTypeRegister = 0x1
	AliasTypeUseAlias = 0x2
	AliasTypeUseValue = 0x3
)

// Location represents a location in a track (Group ID, Object ID)
type Location struct {
	GroupID  uint64
	ObjectID uint64
}

func (l Location) Less(other Location) bool {
	if l.GroupID < other.GroupID {
		return true
	}
	if l.GroupID == other.GroupID {
		return l.ObjectID < other.ObjectID
	}
	return false
}

// TrackNamespace represents a track namespace (tuple of byte fields)
type TrackNamespace struct {
	Fields [][]byte
}

func NewTrackNamespace(fields [][]byte) (*TrackNamespace, error) {
	if len(fields) == 0 || len(fields) > 32 {
		return nil, fmt.Errorf("%w: track namespace must have 1-32 fields, got %d", ErrProtocolViolation, len(fields))
	}
	return &TrackNamespace{Fields: fields}, nil
}

// FullTrackName represents a full track name (namespace + name)
type FullTrackName struct {
	Namespace *TrackNamespace
	Name      []byte
}

func NewFullTrackName(namespace *TrackNamespace, name []byte) (*FullTrackName, error) {
	totalLength := 0
	for _, field := range namespace.Fields {
		totalLength += len(field)
	}
	totalLength += len(name)

	if totalLength > 4096 {
		return nil, fmt.Errorf("%w: full track name exceeds 4096 bytes: %d", ErrProtocolViolation, totalLength)
	}

	return &FullTrackName{
		Namespace: namespace,
		Name:      name,
	}, nil
}

// VarInt provides variable-length integer encoding/decoding as per QUIC spec
type VarInt struct{}

func (VarInt) Encode(value uint64) ([]byte, error) {
	if value < 0x40 {
		return []byte{byte(value)}, nil
	} else if value < 0x4000 {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(value|0x4000))
		return buf, nil
	} else if value < 0x40000000 {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(value|0x80000000))
		return buf, nil
	} else if value < 0x4000000000000000 {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, value|0xC000000000000000)
		return buf, nil
	}
	return nil, errors.New("VarInt value too large")
}

func (VarInt) Decode(r io.Reader) (uint64, int, error) {
	firstByte := make([]byte, 1)
	if _, err := io.ReadFull(r, firstByte); err != nil {
		return 0, 0, err
	}

	prefix := firstByte[0] >> 6

	switch prefix {
	case 0:
		return uint64(firstByte[0]), 1, nil
	case 1:
		buf := make([]byte, 1)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, 1, err
		}
		value := binary.BigEndian.Uint16(append(firstByte, buf...)) & 0x3FFF
		return uint64(value), 2, nil
	case 2:
		buf := make([]byte, 3)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, 1, err
		}
		value := binary.BigEndian.Uint32(append(firstByte, buf...)) & 0x3FFFFFFF
		return uint64(value), 4, nil
	default: // prefix == 3
		buf := make([]byte, 7)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, 1, err
		}
		value := binary.BigEndian.Uint64(append(firstByte, buf...)) & 0x3FFFFFFFFFFFFFFF
		return uint64(value), 8, nil
	}
}

// MoQTValidator is the main validator class for MoQT protocol messages
type MoQTValidator struct {
	currentVersion        uint64
	maxRequestIDClient    uint64
	maxRequestIDServer    uint64
	activeTracks          map[uint64]*FullTrackName // Track alias -> FullTrackName
	activeSubscriptions   map[uint64]interface{}    // Request ID -> subscription info
	activeFetches         map[uint64]interface{}    // Request ID -> fetch info
	authTokens            map[uint64][]byte         // Token alias -> token value
	maxAuthTokenCacheSize uint64
	currentAuthTokenSize  uint64
}

func NewMoQTValidator() *MoQTValidator {
	return &MoQTValidator{
		currentVersion:      0x00000001, // Version 1 of the spec
		activeTracks:        make(map[uint64]*FullTrackName),
		activeSubscriptions: make(map[uint64]interface{}),
		activeFetches:       make(map[uint64]interface{}),
		authTokens:          make(map[uint64][]byte),
	}
}

func (v *MoQTValidator) ValidateMessage(data []byte, isControlStream bool) (map[string]interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty message", ErrValidation)
	}

	r := bytes.NewReader(data)

	if isControlStream {
		return v.validateControlMessage(r)
	}
	return v.validateDataStream(data)
}

func (v *MoQTValidator) validateControlMessage(r io.Reader) (map[string]interface{}, error) {
	var varInt VarInt
	msgType, _, err := varInt.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read message type: %v", ErrValidation, err)
	}

	// Validate message type
	if !isValidMessageType(msgType) {
		return nil, fmt.Errorf("%w: unknown message type: %d", ErrProtocolViolation, msgType)
	}

	// Read message length (16 bits)
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, lengthBytes); err != nil {
		return nil, fmt.Errorf("%w: insufficient data for message length", ErrValidation)
	}
	msgLength := binary.BigEndian.Uint16(lengthBytes)

	// Read message payload
	payload := make([]byte, msgLength)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("%w: message payload incomplete: expected %d bytes", ErrValidation, msgLength)
	}

	result := map[string]interface{}{
		"type":       getMessageTypeName(msgType),
		"type_value": msgType,
		"length":     msgLength,
	}

	payloadReader := bytes.NewReader(payload)

	switch msgType {
	case ClientSetup:
		details, err := v.validateClientSetup(payloadReader)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	case ServerSetup:
		details, err := v.validateServerSetup(payloadReader)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	case Subscribe:
		details, err := v.validateSubscribe(payloadReader)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	case SubscribeOK:
		details, err := v.validateSubscribeOK(payloadReader)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	case Fetch:
		details, err := v.validateFetch(payloadReader)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	case Announce:
		details, err := v.validateAnnounce(payloadReader)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	case Goaway:
		details, err := v.validateGoaway(payloadReader)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	case MaxRequestID:
		details, err := v.validateMaxRequestID(payloadReader)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	case TrackStatusRequest:
		details, err := v.validateTrackStatusRequest(payloadReader)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	default:
		result["raw_payload"] = hex.EncodeToString(payload)
	}

	return result, nil
}

func (v *MoQTValidator) validateClientSetup(r io.Reader) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var varInt VarInt

	// Number of supported versions
	numVersions, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["num_versions"] = numVersions

	// Supported versions
	versions := make([]string, numVersions)
	for i := uint64(0); i < numVersions; i++ {
		version, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		versions[i] = fmt.Sprintf("0x%08x", version)
	}
	result["supported_versions"] = versions

	// Number of parameters
	numParams, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["num_parameters"] = numParams

	// Parameters
	params, err := v.validateSetupParameters(r, numParams)
	if err != nil {
		return nil, err
	}
	result["parameters"] = params

	return result, nil
}

func (v *MoQTValidator) validateServerSetup(r io.Reader) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var varInt VarInt

	// Selected version
	version, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["selected_version"] = fmt.Sprintf("0x%08x", version)

	// Number of parameters
	numParams, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["num_parameters"] = numParams

	// Parameters
	params, err := v.validateSetupParameters(r, numParams)
	if err != nil {
		return nil, err
	}
	result["parameters"] = params

	return result, nil
}

func (v *MoQTValidator) validateSubscribe(r io.Reader) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var varInt VarInt

	// Request ID
	requestID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["request_id"] = requestID
	if err := v.validateRequestID(requestID, true); err != nil {
		return nil, err
	}

	// Track Alias
	trackAlias, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["track_alias"] = trackAlias

	// Track Namespace
	namespace, err := v.readTuple(r)
	if err != nil {
		return nil, err
	}
	namespaceHex := make([]string, len(namespace))
	for i, field := range namespace {
		namespaceHex[i] = hex.EncodeToString(field)
	}
	result["track_namespace"] = namespaceHex

	// Track Name
	nameLength, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	trackName := make([]byte, nameLength)
	if _, err := io.ReadFull(r, trackName); err != nil {
		return nil, fmt.Errorf("%w: insufficient data for track name", ErrValidation)
	}
	result["track_name"] = hex.EncodeToString(trackName)

	// Create FullTrackName and validate
	trackNamespace, err := NewTrackNamespace(namespace)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid track namespace: %v", ErrValidation, err)
	}

	fullTrackName, err := NewFullTrackName(trackNamespace, trackName)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid track name: %v", ErrValidation, err)
	}

	// Subscriber Priority
	priorityByte := make([]byte, 1)
	if _, err := io.ReadFull(r, priorityByte); err != nil {
		return nil, fmt.Errorf("%w: missing subscriber priority", ErrValidation)
	}
	result["subscriber_priority"] = priorityByte[0]

	// Group Order
	orderByte := make([]byte, 1)
	if _, err := io.ReadFull(r, orderByte); err != nil {
		return nil, fmt.Errorf("%w: missing group order", ErrValidation)
	}
	groupOrder := orderByte[0]
	if groupOrder > 2 {
		return nil, fmt.Errorf("%w: invalid group order: %d", ErrProtocolViolation, groupOrder)
	}
	result["group_order"] = getGroupOrderName(groupOrder)

	// Forward
	forwardByte := make([]byte, 1)
	if _, err := io.ReadFull(r, forwardByte); err != nil {
		return nil, fmt.Errorf("%w: missing forward flag", ErrValidation)
	}
	forward := forwardByte[0]
	if forward > 1 {
		return nil, fmt.Errorf("%w: invalid forward value: %d", ErrProtocolViolation, forward)
	}
	result["forward"] = forward == 1

	// Filter Type
	filterType, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	if !isValidFilterType(filterType) {
		return nil, fmt.Errorf("%w: invalid filter type: %d", ErrProtocolViolation, filterType)
	}
	result["filter_type"] = getFilterTypeName(filterType)

	// Start Location (for AbsoluteStart and AbsoluteRange)
	if filterType == AbsoluteStart || filterType == AbsoluteRange {
		startGroup, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		startObject, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["start_location"] = map[string]uint64{
			"group":  startGroup,
			"object": startObject,
		}
	}

	// End Group (for AbsoluteRange)
	if filterType == AbsoluteRange {
		endGroup, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["end_group"] = endGroup

		// Validate range
		if startLoc, ok := result["start_location"].(map[string]uint64); ok {
			if endGroup < startLoc["group"] {
				return nil, fmt.Errorf("%w: end group must be >= start group", ErrValidation)
			}
		}
	}

	// Parameters
	numParams, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["num_parameters"] = numParams

	if numParams > 0 {
		params, err := v.validateVersionParameters(r, numParams)
		if err != nil {
			return nil, err
		}
		result["parameters"] = params
	}

	// Store subscription info
	v.activeSubscriptions[requestID] = map[string]interface{}{
		"track_alias":     trackAlias,
		"full_track_name": fullTrackName,
		"filter_type":     filterType,
	}

	return result, nil
}

func (v *MoQTValidator) validateSubscribeOK(r io.Reader) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var varInt VarInt

	// Request ID
	requestID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["request_id"] = requestID

	// Expires
	expires, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["expires_ms"] = expires

	// Group Order
	orderByte := make([]byte, 1)
	if _, err := io.ReadFull(r, orderByte); err != nil {
		return nil, fmt.Errorf("%w: missing group order", ErrValidation)
	}
	groupOrder := orderByte[0]
	if groupOrder == 0 || groupOrder > 2 {
		return nil, fmt.Errorf("%w: invalid group order in SUBSCRIBE_OK: %d", ErrProtocolViolation, groupOrder)
	}
	result["group_order"] = getGroupOrderName(groupOrder)

	// Content Exists
	existsByte := make([]byte, 1)
	if _, err := io.ReadFull(r, existsByte); err != nil {
		return nil, fmt.Errorf("%w: missing content exists flag", ErrValidation)
	}
	contentExists := existsByte[0]
	if contentExists > 1 {
		return nil, fmt.Errorf("%w: invalid content exists value: %d", ErrProtocolViolation, contentExists)
	}
	result["content_exists"] = contentExists == 1

	// Largest Location (if content exists)
	if contentExists == 1 {
		largestGroup, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		largestObject, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["largest_location"] = map[string]uint64{
			"group":  largestGroup,
			"object": largestObject,
		}
	}

	// Parameters
	numParams, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["num_parameters"] = numParams

	if numParams > 0 {
		params, err := v.validateVersionParameters(r, numParams)
		if err != nil {
			return nil, err
		}
		result["parameters"] = params
	}

	return result, nil
}

func (v *MoQTValidator) validateFetch(r io.Reader) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var varInt VarInt

	// Request ID
	requestID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["request_id"] = requestID
	if err := v.validateRequestID(requestID, true); err != nil {
		return nil, err
	}

	// Subscriber Priority
	priorityByte := make([]byte, 1)
	if _, err := io.ReadFull(r, priorityByte); err != nil {
		return nil, fmt.Errorf("%w: missing subscriber priority", ErrValidation)
	}
	result["subscriber_priority"] = priorityByte[0]

	// Group Order
	orderByte := make([]byte, 1)
	if _, err := io.ReadFull(r, orderByte); err != nil {
		return nil, fmt.Errorf("%w: missing group order", ErrValidation)
	}
	groupOrder := orderByte[0]
	if groupOrder > 2 {
		return nil, fmt.Errorf("%w: invalid group order: %d", ErrProtocolViolation, groupOrder)
	}
	result["group_order"] = getGroupOrderName(groupOrder)

	// Fetch Type
	fetchType, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	if fetchType < 1 || fetchType > 3 {
		return nil, fmt.Errorf("%w: invalid fetch type: %d", ErrProtocolViolation, fetchType)
	}
	fetchTypeNames := []string{"STANDALONE", "RELATIVE_JOINING", "ABSOLUTE_JOINING"}
	result["fetch_type"] = fetchTypeNames[fetchType-1]

	if fetchType == 1 { // Standalone
		// Track Namespace
		namespace, err := v.readTuple(r)
		if err != nil {
			return nil, err
		}
		namespaceHex := make([]string, len(namespace))
		for i, field := range namespace {
			namespaceHex[i] = hex.EncodeToString(field)
		}
		result["track_namespace"] = namespaceHex

		// Track Name
		nameLength, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		trackName := make([]byte, nameLength)
		if _, err := io.ReadFull(r, trackName); err != nil {
			return nil, err
		}
		result["track_name"] = hex.EncodeToString(trackName)

		// Start Group/Object
		startGroup, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		startObject, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["start"] = map[string]uint64{
			"group":  startGroup,
			"object": startObject,
		}

		// End Group/Object
		endGroup, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		endObject, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["end"] = map[string]uint64{
			"group":  endGroup,
			"object": endObject,
		}

		// Validate range
		startLoc := Location{GroupID: startGroup, ObjectID: startObject}
		endLoc := Location{GroupID: endGroup, ObjectID: endObject}
		if endLoc.Less(startLoc) {
			return nil, fmt.Errorf("%w: end location must be >= start location", ErrValidation)
		}
	} else { // Joining fetch
		// Joining Subscribe ID
		subscribeID, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["joining_subscribe_id"] = subscribeID

		// Joining Start
		joiningStart, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["joining_start"] = joiningStart
	}

	// Parameters
	numParams, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["num_parameters"] = numParams

	if numParams > 0 {
		params, err := v.validateVersionParameters(r, numParams)
		if err != nil {
			return nil, err
		}
		result["parameters"] = params
	}

	// Store fetch info
	v.activeFetches[requestID] = result

	return result, nil
}

func (v *MoQTValidator) validateAnnounce(r io.Reader) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var varInt VarInt

	// Request ID
	requestID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["request_id"] = requestID
	if err := v.validateRequestID(requestID, true); err != nil {
		return nil, err
	}

	// Track Namespace
	namespace, err := v.readTuple(r)
	if err != nil {
		return nil, err
	}
	namespaceHex := make([]string, len(namespace))
	for i, field := range namespace {
		namespaceHex[i] = hex.EncodeToString(field)
	}
	result["track_namespace"] = namespaceHex

	// Parameters
	numParams, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["num_parameters"] = numParams

	if numParams > 0 {
		params, err := v.validateVersionParameters(r, numParams)
		if err != nil {
			return nil, err
		}
		result["parameters"] = params
	}

	return result, nil
}

func (v *MoQTValidator) validateGoaway(r io.Reader) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var varInt VarInt

	// New Session URI Length
	uriLength, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}

	if uriLength > 8192 {
		return nil, fmt.Errorf("%w: new session URI too long: %d bytes", ErrProtocolViolation, uriLength)
	}

	// New Session URI
	if uriLength > 0 {
		uri := make([]byte, uriLength)
		if _, err := io.ReadFull(r, uri); err != nil {
			return nil, fmt.Errorf("%w: insufficient data for URI", ErrValidation)
		}
		result["new_session_uri"] = string(uri)
	} else {
		result["new_session_uri"] = nil
	}

	return result, nil
}

func (v *MoQTValidator) validateMaxRequestID(r io.Reader) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var varInt VarInt

	// Request ID
	requestID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["max_request_id"] = requestID

	// Note: In real implementation, we'd track whether this is from client or server
	// and validate accordingly

	return result, nil
}

func (v *MoQTValidator) validateTrackStatusRequest(r io.Reader) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var varInt VarInt

	// Request ID
	requestID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["request_id"] = requestID
	if err := v.validateRequestID(requestID, true); err != nil {
		return nil, err
	}

	// Track Namespace
	namespace, err := v.readTuple(r)
	if err != nil {
		return nil, err
	}
	namespaceHex := make([]string, len(namespace))
	for i, field := range namespace {
		namespaceHex[i] = hex.EncodeToString(field)
	}
	result["track_namespace"] = namespaceHex

	// Track Name
	nameLength, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	trackName := make([]byte, nameLength)
	if _, err := io.ReadFull(r, trackName); err != nil {
		return nil, err
	}
	result["track_name"] = hex.EncodeToString(trackName)

	// Parameters
	numParams, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["num_parameters"] = numParams

	if numParams > 0 {
		params, err := v.validateVersionParameters(r, numParams)
		if err != nil {
			return nil, err
		}
		result["parameters"] = params
	}

	return result, nil
}

func (v *MoQTValidator) validateSetupParameters(r io.Reader, numParams uint64) ([]map[string]interface{}, error) {
	params := make([]map[string]interface{}, 0, numParams)
	var varInt VarInt

	for i := uint64(0); i < numParams; i++ {
		paramType, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}

		paramInfo := map[string]interface{}{"type": paramType}

		if paramType%2 == 0 { // Even - varint value
			value, _, err := varInt.Decode(r)
			if err != nil {
				return nil, err
			}
			paramInfo["value"] = value
		} else { // Odd - length + bytes
			length, _, err := varInt.Decode(r)
			if err != nil {
				return nil, err
			}
			if length > 65535 {
				return nil, fmt.Errorf("%w: parameter length too large: %d", ErrProtocolViolation, length)
			}
			value := make([]byte, length)
			if _, err := io.ReadFull(r, value); err != nil {
				return nil, fmt.Errorf("%w: insufficient data for parameter value", ErrValidation)
			}
			paramInfo["value"] = hex.EncodeToString(value)
			paramInfo["length"] = length
		}

		// Identify known parameter types
		switch paramType {
		case SetupParamPath:
			paramInfo["name"] = "PATH"
		case SetupParamMaxRequestID:
			paramInfo["name"] = "MAX_REQUEST_ID"
		case SetupParamMaxAuthTokenCacheSize:
			paramInfo["name"] = "MAX_AUTH_TOKEN_CACHE_SIZE"
		}

		params = append(params, paramInfo)
	}

	return params, nil
}

func (v *MoQTValidator) validateVersionParameters(r io.Reader, numParams uint64) ([]map[string]interface{}, error) {
	params := make([]map[string]interface{}, 0, numParams)
	var varInt VarInt

	for i := uint64(0); i < numParams; i++ {
		paramType, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}

		paramInfo := map[string]interface{}{"type": paramType}

		var value []byte
		if paramType%2 == 0 { // Even - varint value
			val, _, err := varInt.Decode(r)
			if err != nil {
				return nil, err
			}
			paramInfo["value"] = val
		} else { // Odd - length + bytes
			length, _, err := varInt.Decode(r)
			if err != nil {
				return nil, err
			}
			if length > 65535 {
				return nil, fmt.Errorf("%w: parameter length too large: %d", ErrProtocolViolation, length)
			}
			value = make([]byte, length)
			if _, err := io.ReadFull(r, value); err != nil {
				return nil, fmt.Errorf("%w: insufficient data for parameter value", ErrValidation)
			}
			paramInfo["value"] = hex.EncodeToString(value)
			paramInfo["length"] = length
		}

		// Identify known parameter types
		switch paramType {
		case VersionParamAuthorizationToken:
			paramInfo["name"] = "AUTHORIZATION_TOKEN"
			if len(value) > 0 {
				authDetails, err := v.validateAuthToken(value)
				if err != nil {
					return nil, err
				}
				for k, v := range authDetails {
					paramInfo[k] = v
				}
			}
		case VersionParamDeliveryTimeout:
			paramInfo["name"] = "DELIVERY_TIMEOUT"
		case VersionParamMaxCacheDuration:
			paramInfo["name"] = "MAX_CACHE_DURATION"
		}

		params = append(params, paramInfo)
	}

	return params, nil
}

func (v *MoQTValidator) validateAuthToken(tokenData []byte) (map[string]interface{}, error) {
	r := bytes.NewReader(tokenData)
	result := make(map[string]interface{})
	var varInt VarInt

	// Alias Type
	aliasType, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}

	if aliasType > 3 {
		return nil, fmt.Errorf("%w: invalid alias type: %d", ErrProtocolViolation, aliasType)
	}

	aliasTypeNames := map[uint64]string{
		0: "DELETE",
		1: "REGISTER",
		2: "USE_ALIAS",
		3: "USE_VALUE",
	}
	result["alias_type"] = aliasTypeNames[aliasType]

	// Token Alias (for DELETE, REGISTER, USE_ALIAS)
	if aliasType <= 2 {
		tokenAlias, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["token_alias"] = tokenAlias
	}

	// Token Type and Value (for REGISTER, USE_VALUE)
	if aliasType == 1 || aliasType == 3 {
		tokenType, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["token_type"] = tokenType

		// Token Value (remaining bytes)
		tokenValue, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		result["token_value"] = hex.EncodeToString(tokenValue)
		result["token_value_length"] = len(tokenValue)

		// Handle token registration
		if aliasType == AliasTypeRegister {
			tokenSize := uint64(8 + len(tokenValue))
			if v.currentAuthTokenSize+tokenSize > v.maxAuthTokenCacheSize {
				return nil, fmt.Errorf("%w: auth token cache overflow", ErrProtocolViolation)
			}

			if alias, ok := result["token_alias"].(uint64); ok {
				if _, exists := v.authTokens[alias]; exists {
					return nil, fmt.Errorf("%w: duplicate auth token alias: %d", ErrProtocolViolation, alias)
				}
				v.authTokens[alias] = tokenValue
				v.currentAuthTokenSize += tokenSize
			}
		}
	}

	// Handle token operations
	if aliasType == AliasTypeDelete {
		if alias, ok := result["token_alias"].(uint64); ok {
			if token, exists := v.authTokens[alias]; exists {
				tokenSize := uint64(8 + len(token))
				delete(v.authTokens, alias)
				v.currentAuthTokenSize -= tokenSize
			}
		}
	} else if aliasType == AliasTypeUseAlias {
		if alias, ok := result["token_alias"].(uint64); ok {
			if _, exists := v.authTokens[alias]; !exists {
				return nil, fmt.Errorf("%w: unknown auth token alias: %d", ErrProtocolViolation, alias)
			}
		}
	}

	return result, nil
}

func (v *MoQTValidator) readTuple(r io.Reader) ([][]byte, error) {
	var varInt VarInt
	numFields, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}

	fields := make([][]byte, 0, numFields)
	for i := uint64(0); i < numFields; i++ {
		fieldLength, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		fieldData := make([]byte, fieldLength)
		if _, err := io.ReadFull(r, fieldData); err != nil {
			return nil, fmt.Errorf("%w: insufficient data for tuple field", ErrValidation)
		}
		fields = append(fields, fieldData)
	}

	return fields, nil
}

func (v *MoQTValidator) validateRequestID(requestID uint64, isClient bool) error {
	if isClient {
		// Client IDs are even
		if requestID%2 != 0 {
			return fmt.Errorf("%w: client request ID must be even, got %d", ErrProtocolViolation, requestID)
		}
		if requestID > v.maxRequestIDClient {
			return fmt.Errorf("%w: request ID %d exceeds maximum %d", ErrProtocolViolation, requestID, v.maxRequestIDClient)
		}
	} else {
		// Server IDs are odd
		if requestID%2 != 1 {
			return fmt.Errorf("%w: server request ID must be odd, got %d", ErrProtocolViolation, requestID)
		}
		if requestID > v.maxRequestIDServer {
			return fmt.Errorf("%w: request ID %d exceeds maximum %d", ErrProtocolViolation, requestID, v.maxRequestIDServer)
		}
	}
	return nil
}

func (v *MoQTValidator) validateDataStream(data []byte) (map[string]interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data stream", ErrValidation)
	}

	r := bytes.NewReader(data)
	var varInt VarInt

	// Read stream type
	streamType, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{"stream_type": streamType}

	if streamType >= 0x08 && streamType <= 0x0D {
		// Subgroup header
		details, err := v.validateSubgroupHeader(r, streamType)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	} else if streamType == 0x05 {
		// Fetch header
		details, err := v.validateFetchHeader(r)
		if err != nil {
			return nil, err
		}
		for k, v := range details {
			result[k] = v
		}
	} else {
		return nil, fmt.Errorf("%w: unknown stream type: %d", ErrProtocolViolation, streamType)
	}

	return result, nil
}

func (v *MoQTValidator) validateSubgroupHeader(r io.Reader, headerType uint64) (map[string]interface{}, error) {
	result := map[string]interface{}{"header_type": "SUBGROUP_HEADER"}
	var varInt VarInt

	// Determine header format based on type
	typeInfo := map[uint64]struct {
		subgroupIDPresent bool
		subgroupIDValue   string
		extensionsPresent bool
	}{
		0x08: {false, "0", false},
		0x09: {false, "0", true},
		0x0A: {false, "first_object_id", false},
		0x0B: {false, "first_object_id", true},
		0x0C: {true, "", false},
		0x0D: {true, "", true},
	}

	info, ok := typeInfo[headerType]
	if !ok {
		return nil, fmt.Errorf("%w: invalid subgroup header type: %d", ErrProtocolViolation, headerType)
	}

	result["subgroup_id_present"] = info.subgroupIDPresent
	result["subgroup_id_value"] = info.subgroupIDValue
	result["extensions_present"] = info.extensionsPresent

	// Track Alias
	trackAlias, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["track_alias"] = trackAlias

	// Group ID
	groupID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["group_id"] = groupID

	// Subgroup ID (if present)
	if info.subgroupIDPresent {
		subgroupID, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["subgroup_id"] = subgroupID
	}

	// Publisher Priority
	priorityByte := make([]byte, 1)
	if _, err := io.ReadFull(r, priorityByte); err != nil {
		return nil, fmt.Errorf("%w: missing publisher priority", ErrValidation)
	}
	result["publisher_priority"] = priorityByte[0]

	// Objects following the header
	objects := make([]map[string]interface{}, 0)
	objectCount := 0
	var firstObjectID *uint64
	var lastObjectID uint64

	for {
		obj, err := v.validateSubgroupObject(r, info.extensionsPresent)
		if err != nil {
			if err == io.EOF {
				break
			}
			// Try to determine if we've reached the end of valid data
			if objectCount > 0 {
				break
			}
			return nil, err
		}

		objID := obj["object_id"].(uint64)
		if firstObjectID == nil {
			firstObjectID = &objID
		}

		// Validate object ordering
		if objectCount > 0 && objID <= lastObjectID {
			return nil, fmt.Errorf("%w: object IDs must be ascending, got %d after %d", ErrProtocolViolation, objID, lastObjectID)
		}
		lastObjectID = objID

		objects = append(objects, obj)
		objectCount++
	}

	result["object_count"] = objectCount
	result["objects"] = objects

	// Set subgroup ID for types 0x0A and 0x0B
	if (headerType == 0x0A || headerType == 0x0B) && firstObjectID != nil {
		result["subgroup_id"] = *firstObjectID
	}

	return result, nil
}

func (v *MoQTValidator) validateSubgroupObject(r io.Reader, extensionsPresent bool) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	var varInt VarInt

	// Object ID
	objectID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	obj["object_id"] = objectID

	// Extension Headers Length (if extensions are present)
	if extensionsPresent {
		extLength, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		obj["extension_headers_length"] = extLength

		if extLength > 0 {
			extData := make([]byte, extLength)
			if _, err := io.ReadFull(r, extData); err != nil {
				return nil, fmt.Errorf("%w: insufficient data for extension headers", ErrValidation)
			}
			headers, err := v.validateExtensionHeaders(extData)
			if err != nil {
				return nil, err
			}
			obj["extension_headers"] = headers
		}
	}

	// Object Payload Length
	payloadLength, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	obj["payload_length"] = payloadLength

	// Object Status (only if payload length is 0)
	if payloadLength == 0 {
		status, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		if !isValidObjectStatus(status) {
			return nil, fmt.Errorf("%w: invalid object status: %d", ErrProtocolViolation, status)
		}
		obj["status"] = getObjectStatusName(status)
	} else {
		obj["status"] = "NORMAL"
		// Read payload
		payload := make([]byte, payloadLength)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("%w: insufficient data for object payload", ErrValidation)
		}
		if payloadLength < 100 {
			obj["payload"] = hex.EncodeToString(payload)
		} else {
			obj["payload"] = fmt.Sprintf("<%d bytes>", payloadLength)
		}
	}

	return obj, nil
}

func (v *MoQTValidator) validateFetchHeader(r io.Reader) (map[string]interface{}, error) {
	result := map[string]interface{}{"header_type": "FETCH_HEADER"}
	var varInt VarInt

	// Request ID
	requestID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["request_id"] = requestID

	// Objects following the header
	objects := make([]map[string]interface{}, 0)

	for {
		obj, err := v.validateFetchObject(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			// Try to determine if we've reached the end of valid data
			if len(objects) > 0 {
				break
			}
			return nil, err
		}
		objects = append(objects, obj)
	}

	result["object_count"] = len(objects)
	result["objects"] = objects

	return result, nil
}

func (v *MoQTValidator) validateFetchObject(r io.Reader) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	var varInt VarInt

	// Group ID
	groupID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	obj["group_id"] = groupID

	// Subgroup ID
	subgroupID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	obj["subgroup_id"] = subgroupID

	// Object ID
	objectID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	obj["object_id"] = objectID

	// Publisher Priority
	priorityByte := make([]byte, 1)
	if _, err := io.ReadFull(r, priorityByte); err != nil {
		return nil, fmt.Errorf("%w: missing publisher priority", ErrValidation)
	}
	obj["publisher_priority"] = priorityByte[0]

	// Extension Headers Length
	extLength, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	obj["extension_headers_length"] = extLength

	if extLength > 0 {
		extData := make([]byte, extLength)
		if _, err := io.ReadFull(r, extData); err != nil {
			return nil, fmt.Errorf("%w: insufficient data for extension headers", ErrValidation)
		}
		headers, err := v.validateExtensionHeaders(extData)
		if err != nil {
			return nil, err
		}
		obj["extension_headers"] = headers
	}

	// Object Payload Length
	payloadLength, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	obj["payload_length"] = payloadLength

	// Object Status (only if payload length is 0)
	if payloadLength == 0 {
		status, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		if !isValidObjectStatus(status) {
			return nil, fmt.Errorf("%w: invalid object status: %d", ErrProtocolViolation, status)
		}
		obj["status"] = getObjectStatusName(status)
	} else {
		obj["status"] = "NORMAL"
		// Read payload
		payload := make([]byte, payloadLength)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("%w: insufficient data for object payload", ErrValidation)
		}
		if payloadLength < 100 {
			obj["payload"] = hex.EncodeToString(payload)
		} else {
			obj["payload"] = fmt.Sprintf("<%d bytes>", payloadLength)
		}
	}

	return obj, nil
}

func (v *MoQTValidator) validateExtensionHeaders(data []byte) ([]map[string]interface{}, error) {
	headers := make([]map[string]interface{}, 0)
	r := bytes.NewReader(data)
	var varInt VarInt

	for r.Len() > 0 {
		header := make(map[string]interface{})

		// Type
		headerType, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		header["type"] = headerType

		if headerType == ExtHeaderPriorGroupIDGap {
			header["name"] = "PRIOR_GROUP_ID_GAP"
		}

		if headerType%2 == 0 { // Even - varint value
			value, _, err := varInt.Decode(r)
			if err != nil {
				return nil, err
			}
			header["value"] = value
		} else { // Odd - length + bytes
			length, _, err := varInt.Decode(r)
			if err != nil {
				return nil, err
			}
			value := make([]byte, length)
			if _, err := io.ReadFull(r, value); err != nil {
				return nil, fmt.Errorf("%w: insufficient data for extension header value", ErrValidation)
			}
			header["value"] = hex.EncodeToString(value)
			header["length"] = length
		}

		headers = append(headers, header)
	}

	return headers, nil
}

func (v *MoQTValidator) ValidateDatagram(data []byte) (map[string]interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty datagram", ErrValidation)
	}

	r := bytes.NewReader(data)
	var varInt VarInt

	// Read type
	datagramType, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}

	if !isValidDatagramType(datagramType) {
		return nil, fmt.Errorf("%w: unknown datagram type: %d", ErrProtocolViolation, datagramType)
	}

	result := map[string]interface{}{
		"type":       getDatagramTypeName(datagramType),
		"type_value": datagramType,
	}

	// Track Alias
	trackAlias, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["track_alias"] = trackAlias

	// Group ID
	groupID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["group_id"] = groupID

	// Object ID
	objectID, _, err := varInt.Decode(r)
	if err != nil {
		return nil, err
	}
	result["object_id"] = objectID

	// Publisher Priority
	priorityByte := make([]byte, 1)
	if _, err := io.ReadFull(r, priorityByte); err != nil {
		return nil, fmt.Errorf("%w: missing publisher priority", ErrValidation)
	}
	result["publisher_priority"] = priorityByte[0]

	// Extension headers (for types with extensions)
	if datagramType == ObjectDatagramWithExt || datagramType == ObjectStatusWithExt {
		extLength, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		result["extension_headers_length"] = extLength

		if extLength > 0 {
			extData := make([]byte, extLength)
			if _, err := io.ReadFull(r, extData); err != nil {
				return nil, fmt.Errorf("%w: insufficient data for extension headers", ErrValidation)
			}
			headers, err := v.validateExtensionHeaders(extData)
			if err != nil {
				return nil, err
			}
			result["extension_headers"] = headers
		} else if extLength == 0 {
			return nil, fmt.Errorf("%w: extension header length is 0 for type with extensions", ErrProtocolViolation)
		}
	}

	// Object payload or status
	if datagramType == ObjectDatagramNoExt || datagramType == ObjectDatagramWithExt {
		// Remaining bytes are payload
		payload, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		result["payload_length"] = len(payload)
		if len(payload) < 100 {
			result["payload"] = hex.EncodeToString(payload)
		} else {
			result["payload"] = fmt.Sprintf("<%d bytes>", len(payload))
		}
	} else {
		// Object status
		status, _, err := varInt.Decode(r)
		if err != nil {
			return nil, err
		}
		if !isValidObjectStatus(status) {
			return nil, fmt.Errorf("%w: invalid object status: %d", ErrProtocolViolation, status)
		}
		result["status"] = getObjectStatusName(status)
	}

	return result, nil
}

// Helper functions

func isValidMessageType(msgType uint64) bool {
	validTypes := []uint64{
		ClientSetup, ServerSetup, Goaway, MaxRequestID, RequestsBlocked,
		Subscribe, SubscribeOK, SubscribeError, Unsubscribe, SubscribeUpdate, SubscribeDone,
		Fetch, FetchOK, FetchError, FetchCancel,
		TrackStatusRequest, TrackStatus,
		Announce, AnnounceOK, AnnounceError, Unannounce, AnnounceCancel,
		SubscribeAnnounces, SubscribeAnnouncesOK, SubscribeAnnouncesError, UnsubscribeAnnounces,
	}

	for _, valid := range validTypes {
		if msgType == valid {
			return true
		}
	}
	return false
}

func getMessageTypeName(msgType uint64) string {
	names := map[uint64]string{
		ClientSetup:             "CLIENT_SETUP",
		ServerSetup:             "SERVER_SETUP",
		Goaway:                  "GOAWAY",
		MaxRequestID:            "MAX_REQUEST_ID",
		RequestsBlocked:         "REQUESTS_BLOCKED",
		Subscribe:               "SUBSCRIBE",
		SubscribeOK:             "SUBSCRIBE_OK",
		SubscribeError:          "SUBSCRIBE_ERROR",
		Unsubscribe:             "UNSUBSCRIBE",
		SubscribeUpdate:         "SUBSCRIBE_UPDATE",
		SubscribeDone:           "SUBSCRIBE_DONE",
		Fetch:                   "FETCH",
		FetchOK:                 "FETCH_OK",
		FetchError:              "FETCH_ERROR",
		FetchCancel:             "FETCH_CANCEL",
		TrackStatusRequest:      "TRACK_STATUS_REQUEST",
		TrackStatus:             "TRACK_STATUS",
		Announce:                "ANNOUNCE",
		AnnounceOK:              "ANNOUNCE_OK",
		AnnounceError:           "ANNOUNCE_ERROR",
		Unannounce:              "UNANNOUNCE",
		AnnounceCancel:          "ANNOUNCE_CANCEL",
		SubscribeAnnounces:      "SUBSCRIBE_ANNOUNCES",
		SubscribeAnnouncesOK:    "SUBSCRIBE_ANNOUNCES_OK",
		SubscribeAnnouncesError: "SUBSCRIBE_ANNOUNCES_ERROR",
		UnsubscribeAnnounces:    "UNSUBSCRIBE_ANNOUNCES",
	}

	if name, ok := names[msgType]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", msgType)
}

func isValidFilterType(filterType uint64) bool {
	return filterType >= NextGroupStart && filterType <= AbsoluteRange
}

func getFilterTypeName(filterType uint64) string {
	names := map[uint64]string{
		NextGroupStart: "NEXT_GROUP_START",
		LatestObject:   "LATEST_OBJECT",
		AbsoluteStart:  "ABSOLUTE_START",
		AbsoluteRange:  "ABSOLUTE_RANGE",
	}

	if name, ok := names[filterType]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", filterType)
}

func getGroupOrderName(order uint8) string {
	switch order {
	case GroupOrderDefault:
		return "DEFAULT"
	case GroupOrderAscending:
		return "ASCENDING"
	case GroupOrderDescending:
		return "DESCENDING"
	default:
		return fmt.Sprintf("UNKNOWN_%d", order)
	}
}

func isValidObjectStatus(status uint64) bool {
	return status == ObjectStatusNormal ||
		status == ObjectStatusDoesNotExist ||
		status == ObjectStatusEndOfGroup ||
		status == ObjectStatusEndOfTrack
}

func getObjectStatusName(status uint64) string {
	names := map[uint64]string{
		ObjectStatusNormal:       "NORMAL",
		ObjectStatusDoesNotExist: "OBJECT_DOES_NOT_EXIST",
		ObjectStatusEndOfGroup:   "END_OF_GROUP",
		ObjectStatusEndOfTrack:   "END_OF_TRACK",
	}

	if name, ok := names[status]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", status)
}

func isValidDatagramType(datagramType uint64) bool {
	return datagramType >= ObjectDatagramNoExt && datagramType <= ObjectStatusWithExt
}

func getDatagramTypeName(datagramType uint64) string {
	names := map[uint64]string{
		ObjectDatagramNoExt:   "OBJECT_DATAGRAM_NO_EXT",
		ObjectDatagramWithExt: "OBJECT_DATAGRAM_WITH_EXT",
		ObjectStatusNoExt:     "OBJECT_STATUS_NO_EXT",
		ObjectStatusWithExt:   "OBJECT_STATUS_WITH_EXT",
	}

	if name, ok := names[datagramType]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", datagramType)
}

func printValidationResult(result map[string]interface{}, indent int) {
	prefix := ""
	for i := 0; i < indent; i++ {
		prefix += "  "
	}

	for key, value := range result {
		switch v := value.(type) {
		case []interface{}:
			fmt.Printf("%s%s:\n", prefix, key)
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					printValidationResult(m, indent+1)
				} else {
					fmt.Printf("%s  - %v\n", prefix, item)
				}
			}
		case []map[string]interface{}:
			fmt.Printf("%s%s:\n", prefix, key)
			for _, item := range v {
				printValidationResult(item, indent+1)
			}
		case map[string]interface{}:
			fmt.Printf("%s%s:\n", prefix, key)
			printValidationResult(v, indent+1)
		case []string:
			fmt.Printf("%s%s:\n", prefix, key)
			for _, item := range v {
				fmt.Printf("%s  - %s\n", prefix, item)
			}
		default:
			fmt.Printf("%s%s: %v\n", prefix, key, value)
		}
	}
}

func main() {
	var (
		hexData  = flag.String("hex", "", "Validate hex-encoded message")
		filePath = flag.String("file", "", "Validate message from file")
		msgType  = flag.String("type", "control", "Message type (control, stream, datagram)")
		jsonOut  = flag.Bool("json", false, "Output as JSON")
	)

	flag.Parse()

	validator := NewMoQTValidator()

	var data []byte
	var err error

	// Get data
	if *hexData != "" {
		// Remove spaces and decode hex
		cleanHex := ""
		for _, c := range *hexData {
			if c != ' ' && c != '\t' && c != '\n' {
				cleanHex += string(c)
			}
		}
		data, err = hex.DecodeString(cleanHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding hex: %v\n", err)
			os.Exit(1)
		}
	} else if *filePath != "" {
		data, err = os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Please provide either -hex or -file")
		flag.Usage()
		os.Exit(1)
	}

	// Validate
	var result map[string]interface{}

	switch *msgType {
	case "control":
		result, err = validator.ValidateMessage(data, true)
	case "stream":
		result, err = validator.validateDataStream(data)
	case "datagram":
		result, err = validator.ValidateDatagram(data)
	default:
		fmt.Fprintf(os.Stderr, "Invalid message type: %s\n", *msgType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Validation failed: %v\n", err)
		os.Exit(1)
	}

	// Output result
	if *jsonOut {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("\n=== MoQT %s Message Validation ===\n", strings.ToUpper(*msgType))
		printValidationResult(result, 0)
		fmt.Println("\n✓ Validation successful")
	}
}
