package scanner

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	pkcs12Version              = 3
	maxPKCS12ContentInfos      = 256
	maxPKCS12Bags              = 10_000
	maxPKCS12BagAttributes     = 64
	maxPKCS12SafeContentsDepth = 16
)

// PKCS#12 format and entry names reported for contained certificates.
const (
	KeystoreFormatPKCS12       = "PKCS#12"
	KeystoreEntryPKCS12CertBag = "certBag"
)

var (
	oidPKCS7Data          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidPKCS7EncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidPKCS12KeyBag               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPKCS12ShroudedKeyBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidPKCS12CertBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidPKCS12SecretBag            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	oidPKCS12SafeContentsBag      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	oidPKCS12X509Certificate      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidPKCS12FriendlyName         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidPBES2                      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBEWithSHAAnd128BitRC4     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}
	oidPBEWithSHAAnd40BitRC4      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 2}
	oidPBEWithSHAAnd3KeyTripleDES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHAAnd2KeyTripleDES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
	oidPBEWithSHAAnd128BitRC2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
	oidPBEWithSHAAnd40BitRC2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
)

type pkcs12Certificate struct {
	certificate *x509.Certificate
	keystore    KeystoreInfo
}

type pkcs12Parser struct {
	certificates []pkcs12Certificate
	encrypted    []PKCS12EncryptedContent
	errors       []error
	bagCount     int
	keyBagCount  int
}

type derElementHeader struct {
	tag           byte
	contentOffset int
	end           int
}

func detectPKCS12(data []byte) bool {
	outer, ok := readDERElementHeader(data, 0, int(^uint(0)>>1))
	if !ok || outer.tag != 0x30 {
		return false
	}
	version, ok := readDERElementHeader(data, outer.contentOffset, outer.end)
	if !ok || version.tag != 0x02 || version.end > len(data) || version.end-version.contentOffset != 1 ||
		data[version.contentOffset] != pkcs12Version {
		return false
	}
	authSafe, ok := readDERElementHeader(data, version.end, outer.end)
	if !ok || authSafe.tag != 0x30 {
		return false
	}
	contentType, ok := readDERElementHeader(data, authSafe.contentOffset, authSafe.end)
	if !ok || contentType.tag != 0x06 || contentType.end > len(data) {
		return false
	}
	var oid asn1.ObjectIdentifier
	if err := unmarshalExact(data[authSafe.contentOffset:contentType.end], &oid); err != nil {
		return false
	}
	if !oid.Equal(oidPKCS7Data) && !oid.Equal(oidPKCS7SignedData) {
		return false
	}
	content, ok := readDERElementHeader(data, contentType.end, authSafe.end)
	return ok && content.tag == 0xa0
}

func readDERElementHeader(data []byte, offset, limit int) (derElementHeader, bool) {
	if offset < 0 || offset+2 > len(data) || offset >= limit {
		return derElementHeader{}, false
	}
	tag := data[offset]
	offset++
	firstLength := data[offset]
	offset++
	var length uint64
	if firstLength&0x80 == 0 {
		length = uint64(firstLength)
	} else {
		lengthBytes := int(firstLength & 0x7f)
		if lengthBytes == 0 || lengthBytes > 8 || offset+lengthBytes > len(data) || data[offset] == 0 {
			return derElementHeader{}, false
		}
		for _, value := range data[offset : offset+lengthBytes] {
			length = length<<8 | uint64(value)
		}
		if length < 128 {
			return derElementHeader{}, false
		}
		offset += lengthBytes
	}
	maxInt := uint64(^uint(0) >> 1)
	if length > maxInt || uint64(offset) > maxInt-length {
		return derElementHeader{}, false
	}
	end := offset + int(length)
	if end > limit {
		return derElementHeader{}, false
	}
	return derElementHeader{tag: tag, contentOffset: offset, end: end}, true
}

func parsePKCS12(data []byte) ([]pkcs12Certificate, []PKCS12EncryptedContent, error) {
	outer, err := rawSequenceElements(data, "PFX", 3)
	if err != nil {
		return nil, nil, err
	}
	if len(outer) < 2 || len(outer) > 3 {
		return nil, nil, fmt.Errorf("PFX has %d fields, want 2 or 3", len(outer))
	}
	version, err := rawInteger(outer[0])
	if err != nil {
		return nil, nil, fmt.Errorf("PFX version: %w", err)
	}
	if version != pkcs12Version {
		return nil, nil, fmt.Errorf("unsupported PFX version %d", version)
	}
	authSafeType, authSafeValue, err := parseContentInfo(outer[1])
	if err != nil {
		return nil, nil, fmt.Errorf("PFX authSafe: %w", err)
	}
	if !authSafeType.Equal(oidPKCS7Data) {
		return nil, nil, fmt.Errorf("unsupported PFX authSafe content type %s", authSafeType.String())
	}
	authenticatedSafe, err := explicitOctets(authSafeValue)
	if err != nil {
		return nil, nil, fmt.Errorf("PFX authSafe data: %w", err)
	}
	contentInfos, err := rawSequenceElements(authenticatedSafe, "AuthenticatedSafe", maxPKCS12ContentInfos)
	if err != nil {
		return nil, nil, err
	}

	parser := pkcs12Parser{}
	for contentIndex, encodedContentInfo := range contentInfos {
		contentType, contentValue, contentErr := parseContentInfo(encodedContentInfo)
		if contentErr != nil {
			parser.errors = append(parser.errors, fmt.Errorf("content %d: %w", contentIndex, contentErr))
			continue
		}
		switch {
		case contentType.Equal(oidPKCS7Data):
			safeContents, decodeErr := explicitOctets(contentValue)
			if decodeErr != nil {
				parser.errors = append(parser.errors, fmt.Errorf("content %d data: %w", contentIndex, decodeErr))
				continue
			}
			chainIndex := 0
			if parseErr := parser.parseSafeContents(safeContents, 0, &chainIndex); parseErr != nil {
				parser.errors = append(parser.errors, fmt.Errorf("content %d SafeContents: %w", contentIndex, parseErr))
			}
		case contentType.Equal(oidPKCS7EncryptedData):
			finding, findingErr := parseEncryptedContent(contentValue, contentIndex)
			if findingErr != nil {
				parser.errors = append(parser.errors, fmt.Errorf("content %d encryptedData: %w", contentIndex, findingErr))
				continue
			}
			parser.encrypted = append(parser.encrypted, finding)
		default:
			parser.errors = append(
				parser.errors,
				fmt.Errorf("content %d has unsupported content type %s", contentIndex, contentType.String()),
			)
		}
	}

	truststore := len(parser.certificates) > 0 && parser.keyBagCount == 0 && len(parser.encrypted) == 0
	for index := range parser.certificates {
		parser.certificates[index].keystore.Truststore = truststore
	}
	return parser.certificates, parser.encrypted, errors.Join(parser.errors...)
}

func (parser *pkcs12Parser) parseSafeContents(
	encoded []byte,
	depth int,
	chainIndex *int,
) error {
	if depth > maxPKCS12SafeContentsDepth {
		return fmt.Errorf("nesting depth exceeds %d", maxPKCS12SafeContentsDepth)
	}
	bags, err := rawSequenceElements(encoded, "SafeContents", maxPKCS12Bags+1)
	if err != nil {
		return err
	}
	var parseErrors []error
	for bagIndex, encodedBag := range bags {
		parser.bagCount++
		if parser.bagCount > maxPKCS12Bags {
			return errors.Join(errors.Join(parseErrors...), fmt.Errorf("bag count exceeds %d", maxPKCS12Bags))
		}
		bagID, bagValue, attributes, bagErr := parseSafeBag(encodedBag)
		if bagErr != nil {
			parseErrors = append(parseErrors, fmt.Errorf("bag %d: %w", bagIndex, bagErr))
			continue
		}
		switch {
		case bagID.Equal(oidPKCS12KeyBag), bagID.Equal(oidPKCS12ShroudedKeyBag), bagID.Equal(oidPKCS12SecretBag):
			parser.keyBagCount++
		case bagID.Equal(oidPKCS12CertBag):
			position := *chainIndex
			(*chainIndex)++
			friendlyName, nameErr := parseFriendlyName(attributes)
			if nameErr != nil {
				parseErrors = append(parseErrors, fmt.Errorf("bag %d friendlyName: %w", bagIndex, nameErr))
			}
			der, certErr := parsePKCS12CertificateBag(bagValue)
			if certErr != nil {
				parseErrors = append(parseErrors, fmt.Errorf("bag %d certBag: %w", bagIndex, certErr))
				continue
			}
			certificate, certErr := x509.ParseCertificate(der)
			if certErr != nil {
				parseErrors = append(parseErrors, fmt.Errorf("bag %d X.509 DER: %w", bagIndex, certErr))
				continue
			}
			parser.certificates = append(parser.certificates, pkcs12Certificate{
				certificate: certificate,
				keystore: KeystoreInfo{
					Format:       KeystoreFormatPKCS12,
					FriendlyName: friendlyName,
					EntryType:    KeystoreEntryPKCS12CertBag,
					ChainIndex:   position,
				},
			})
		case bagID.Equal(oidPKCS12SafeContentsBag):
			if nestedErr := parser.parseSafeContents(bagValue.Bytes, depth+1, chainIndex); nestedErr != nil {
				parseErrors = append(parseErrors, fmt.Errorf("bag %d nested SafeContents: %w", bagIndex, nestedErr))
			}
		}
	}
	return errors.Join(parseErrors...)
}

func parseSafeBag(encoded asn1.RawValue) (
	asn1.ObjectIdentifier,
	asn1.RawValue,
	*asn1.RawValue,
	error,
) {
	elements, err := rawSequenceElements(encoded.FullBytes, "SafeBag", 3)
	if err != nil {
		return nil, asn1.RawValue{}, nil, err
	}
	if len(elements) < 2 || len(elements) > 3 {
		return nil, asn1.RawValue{}, nil, fmt.Errorf("has %d fields, want 2 or 3", len(elements))
	}
	bagID, err := rawOID(elements[0])
	if err != nil {
		return nil, asn1.RawValue{}, nil, fmt.Errorf("bag ID: %w", err)
	}
	bagValue := elements[1]
	if bagValue.Class != asn1.ClassContextSpecific || bagValue.Tag != 0 || !bagValue.IsCompound {
		return nil, asn1.RawValue{}, nil, errors.New("bag value is not [0] EXPLICIT")
	}
	if len(elements) == 2 {
		return bagID, bagValue, nil, nil
	}
	attributes := elements[2]
	if attributes.Class != asn1.ClassUniversal || attributes.Tag != asn1.TagSet || !attributes.IsCompound {
		return nil, asn1.RawValue{}, nil, errors.New("bag attributes are not a SET")
	}
	return bagID, bagValue, &attributes, nil
}

func parsePKCS12CertificateBag(value asn1.RawValue) ([]byte, error) {
	elements, err := rawSequenceElements(value.Bytes, "CertBag", 2)
	if err != nil {
		return nil, err
	}
	if len(elements) != 2 {
		return nil, fmt.Errorf("has %d fields, want 2", len(elements))
	}
	certificateType, err := rawOID(elements[0])
	if err != nil {
		return nil, fmt.Errorf("certificate type: %w", err)
	}
	if !certificateType.Equal(oidPKCS12X509Certificate) {
		return nil, fmt.Errorf("unsupported certificate type %s", certificateType.String())
	}
	certificateValue := elements[1]
	if certificateValue.Class != asn1.ClassContextSpecific || certificateValue.Tag != 0 || !certificateValue.IsCompound {
		return nil, errors.New("certificate value is not [0] EXPLICIT")
	}
	var der []byte
	if err := unmarshalExact(certificateValue.Bytes, &der); err != nil {
		return nil, fmt.Errorf("certificate OCTET STRING: %w", err)
	}
	return der, nil
}

func parseFriendlyName(attributes *asn1.RawValue) (string, error) {
	if attributes == nil {
		return "", nil
	}
	rest := attributes.Bytes
	for attributeIndex := 0; len(rest) > 0; attributeIndex++ {
		if attributeIndex >= maxPKCS12BagAttributes {
			return "", fmt.Errorf("attribute count exceeds %d", maxPKCS12BagAttributes)
		}
		var attribute asn1.RawValue
		remaining, err := asn1.Unmarshal(rest, &attribute)
		if err != nil {
			return "", fmt.Errorf("attribute %d: %w", attributeIndex, err)
		}
		rest = remaining
		elements, err := rawSequenceElements(attribute.FullBytes, "attribute", 2)
		if err != nil {
			return "", fmt.Errorf("attribute %d: %w", attributeIndex, err)
		}
		if len(elements) != 2 {
			return "", fmt.Errorf("attribute %d has %d fields, want 2", attributeIndex, len(elements))
		}
		attributeID, err := rawOID(elements[0])
		if err != nil {
			return "", fmt.Errorf("attribute %d ID: %w", attributeIndex, err)
		}
		if !attributeID.Equal(oidPKCS12FriendlyName) {
			continue
		}
		values := elements[1]
		if values.Class != asn1.ClassUniversal || values.Tag != asn1.TagSet || !values.IsCompound {
			return "", errors.New("friendlyName values are not a SET")
		}
		var value asn1.RawValue
		remaining, err = asn1.Unmarshal(values.Bytes, &value)
		if err != nil {
			return "", fmt.Errorf("friendlyName value: %w", err)
		}
		if len(remaining) != 0 {
			return "", errors.New("friendlyName has multiple values")
		}
		return decodePKCS12String(value)
	}
	return "", nil
}

func decodePKCS12String(value asn1.RawValue) (string, error) {
	if value.Class != asn1.ClassUniversal {
		return "", errors.New("string uses a non-universal ASN.1 class")
	}
	switch value.Tag {
	case asn1.TagUTF8String:
		if !utf8.Valid(value.Bytes) {
			return "", errors.New("invalid UTF-8 string")
		}
		return string(value.Bytes), nil
	case asn1.TagPrintableString, asn1.TagIA5String:
		return string(value.Bytes), nil
	case 30: // BMPString, encoded as UTF-16 big-endian.
		return decodeUTF16BE(value.Bytes)
	default:
		return "", fmt.Errorf("unsupported ASN.1 string tag %d", value.Tag)
	}
}

func decodeUTF16BE(encoded []byte) (string, error) {
	if len(encoded)%2 != 0 {
		return "", errors.New("odd-length BMPString")
	}
	units := make([]uint16, len(encoded)/2)
	for index := range units {
		units[index] = uint16(encoded[index*2])<<8 | uint16(encoded[index*2+1])
	}
	runes := make([]rune, 0, len(units))
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+1 >= len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return "", fmt.Errorf("unpaired high surrogate at code unit %d", index)
			}
			runes = append(runes, utf16.DecodeRune(rune(unit), rune(units[index+1])))
			index++
		case unit >= 0xdc00 && unit <= 0xdfff:
			return "", fmt.Errorf("unpaired low surrogate at code unit %d", index)
		default:
			runes = append(runes, rune(unit))
		}
	}
	return string(runes), nil
}

func parseEncryptedContent(value asn1.RawValue, contentIndex int) (PKCS12EncryptedContent, error) {
	elements, err := rawSequenceElements(value.Bytes, "EncryptedData", 3)
	if err != nil {
		return PKCS12EncryptedContent{}, err
	}
	if len(elements) < 2 || len(elements) > 3 {
		return PKCS12EncryptedContent{}, fmt.Errorf("has %d fields, want 2 or 3", len(elements))
	}
	version, err := rawInteger(elements[0])
	if err != nil {
		return PKCS12EncryptedContent{}, fmt.Errorf("version: %w", err)
	}
	if version != 0 {
		return PKCS12EncryptedContent{}, fmt.Errorf("unsupported version %d", version)
	}
	encryptedContentInfo, err := rawSequenceElements(elements[1].FullBytes, "EncryptedContentInfo", 3)
	if err != nil {
		return PKCS12EncryptedContent{}, err
	}
	if len(encryptedContentInfo) < 2 || len(encryptedContentInfo) > 3 {
		return PKCS12EncryptedContent{}, fmt.Errorf(
			"EncryptedContentInfo has %d fields, want 2 or 3",
			len(encryptedContentInfo),
		)
	}
	contentType, err := rawOID(encryptedContentInfo[0])
	if err != nil {
		return PKCS12EncryptedContent{}, fmt.Errorf("encrypted content type: %w", err)
	}
	if !contentType.Equal(oidPKCS7Data) {
		return PKCS12EncryptedContent{}, fmt.Errorf("unsupported encrypted content type %s", contentType.String())
	}
	if len(encryptedContentInfo) == 3 {
		content := encryptedContentInfo[2]
		if content.Class != asn1.ClassContextSpecific || content.Tag != 0 {
			return PKCS12EncryptedContent{}, errors.New("encrypted content is not [0] IMPLICIT")
		}
	}
	algorithmIdentifier, err := rawSequenceElements(
		encryptedContentInfo[1].FullBytes,
		"content encryption algorithm",
		2,
	)
	if err != nil {
		return PKCS12EncryptedContent{}, err
	}
	if len(algorithmIdentifier) < 1 || len(algorithmIdentifier) > 2 {
		return PKCS12EncryptedContent{}, fmt.Errorf("algorithm identifier has %d fields", len(algorithmIdentifier))
	}
	algorithmOID, err := rawOID(algorithmIdentifier[0])
	if err != nil {
		return PKCS12EncryptedContent{}, fmt.Errorf("algorithm OID: %w", err)
	}
	return PKCS12EncryptedContent{
		ContentIndex: contentIndex,
		Algorithm:    pkcs12AlgorithmName(algorithmOID),
		AlgorithmOID: algorithmOID.String(),
		BagCount:     nil,
	}, nil
}

func pkcs12AlgorithmName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidPBES2):
		return "PBES2"
	case oid.Equal(oidPBEWithSHAAnd128BitRC4):
		return "pbeWithSHAAnd128BitRC4"
	case oid.Equal(oidPBEWithSHAAnd40BitRC4):
		return "pbeWithSHAAnd40BitRC4"
	case oid.Equal(oidPBEWithSHAAnd3KeyTripleDES):
		return "pbeWithSHAAnd3-KeyTripleDES-CBC"
	case oid.Equal(oidPBEWithSHAAnd2KeyTripleDES):
		return "pbeWithSHAAnd2-KeyTripleDES-CBC"
	case oid.Equal(oidPBEWithSHAAnd128BitRC2):
		return "pbeWithSHAAnd128BitRC2-CBC"
	case oid.Equal(oidPBEWithSHAAnd40BitRC2):
		return "pbeWithSHAAnd40BitRC2-CBC"
	default:
		return "unknown"
	}
}

func parseContentInfo(encoded asn1.RawValue) (asn1.ObjectIdentifier, asn1.RawValue, error) {
	elements, err := rawSequenceElements(encoded.FullBytes, "ContentInfo", 2)
	if err != nil {
		return nil, asn1.RawValue{}, err
	}
	if len(elements) != 2 {
		return nil, asn1.RawValue{}, fmt.Errorf("has %d fields, want 2", len(elements))
	}
	contentType, err := rawOID(elements[0])
	if err != nil {
		return nil, asn1.RawValue{}, fmt.Errorf("content type: %w", err)
	}
	content := elements[1]
	if content.Class != asn1.ClassContextSpecific || content.Tag != 0 || !content.IsCompound {
		return nil, asn1.RawValue{}, errors.New("content is not [0] EXPLICIT")
	}
	return contentType, content, nil
}

func explicitOctets(value asn1.RawValue) ([]byte, error) {
	var result []byte
	if err := unmarshalExact(value.Bytes, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func rawSequenceElements(encoded []byte, context string, maximum int) ([]asn1.RawValue, error) {
	var sequence asn1.RawValue
	if err := unmarshalExact(encoded, &sequence); err != nil {
		return nil, fmt.Errorf("%s: %w", context, err)
	}
	if sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, fmt.Errorf("%s is not a SEQUENCE", context)
	}
	result := make([]asn1.RawValue, 0, min(maximum, 16))
	rest := sequence.Bytes
	for len(rest) > 0 {
		if len(result) >= maximum {
			return nil, fmt.Errorf("%s element count exceeds %d", context, maximum)
		}
		var element asn1.RawValue
		remaining, err := asn1.Unmarshal(rest, &element)
		if err != nil {
			return nil, fmt.Errorf("%s element %d: %w", context, len(result), err)
		}
		if len(remaining) >= len(rest) {
			return nil, fmt.Errorf("%s element %d made no parsing progress", context, len(result))
		}
		result = append(result, element)
		rest = remaining
	}
	return result, nil
}

func rawOID(value asn1.RawValue) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	if err := unmarshalExact(value.FullBytes, &oid); err != nil {
		return nil, err
	}
	return oid, nil
}

func rawInteger(value asn1.RawValue) (int, error) {
	var result int
	if err := unmarshalExact(value.FullBytes, &result); err != nil {
		return 0, err
	}
	return result, nil
}

func unmarshalExact(encoded []byte, value any) error {
	rest, err := asn1.Unmarshal(encoded, value)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("%d trailing bytes", len(rest))
	}
	return nil
}
