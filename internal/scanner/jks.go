package scanner

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

const (
	jksMagic   uint32 = 0xfeedfeed
	jceksMagic uint32 = 0xcececece

	javaKeystoreMACSize = 20

	keystoreTagPrivateKey uint32 = 1
	keystoreTagTrusted    uint32 = 2
	keystoreTagSecretKey  uint32 = 3
)

// Java keystore formats and entry types reported for contained certificates.
const (
	KeystoreFormatJKS            = "JKS"
	KeystoreFormatJCEKS          = "JCEKS"
	KeystoreEntryPrivateKey      = "PrivateKeyEntry"
	KeystoreEntryTrustedCert     = "trustedCertEntry"
	javaKeystoreCertificateType  = "X.509"
	minimumJavaKeystoreFileBytes = 12 + javaKeystoreMACSize
)

type javaKeystoreCertificate struct {
	certificate *x509.Certificate
	keystore    KeystoreInfo
}

type javaKeystoreReader struct {
	data   []byte
	offset int
}

func detectJavaKeystore(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	switch binary.BigEndian.Uint32(data[:4]) {
	case jksMagic:
		return KeystoreFormatJKS, true
	case jceksMagic:
		return KeystoreFormatJCEKS, true
	default:
		return "", false
	}
}

func parseJavaKeystore(data []byte) ([]javaKeystoreCertificate, error) {
	format, detected := detectJavaKeystore(data)
	if !detected {
		return nil, errors.New("unrecognized Java keystore magic")
	}
	if len(data) < minimumJavaKeystoreFileBytes {
		return nil, fmt.Errorf("truncated %s header or integrity MAC", format)
	}

	reader := javaKeystoreReader{data: data[:len(data)-javaKeystoreMACSize]}
	if _, err := reader.uint32(); err != nil {
		return nil, fmt.Errorf("read %s magic: %w", format, err)
	}
	version, err := reader.uint32()
	if err != nil {
		return nil, fmt.Errorf("read %s version: %w", format, err)
	}
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("unsupported %s version %d", format, version)
	}
	entryCount, err := reader.uint32()
	if err != nil {
		return nil, fmt.Errorf("read %s entry count: %w", format, err)
	}
	if entryCount == 0 {
		return nil, fmt.Errorf("%s contains zero entries", format)
	}

	var certificates []javaKeystoreCertificate
	var parseErrors []error
	privateKeyEntries := 0
	trustedEntries := 0
	for entryIndex := range entryCount {
		tag, readErr := reader.uint32()
		if readErr != nil {
			return certificates, errors.Join(errors.Join(parseErrors...), fmt.Errorf("entry %d tag: %w", entryIndex, readErr))
		}
		aliasBytes, readErr := reader.lengthPrefixedUint16()
		if readErr != nil {
			return certificates, errors.Join(errors.Join(parseErrors...), fmt.Errorf("entry %d alias: %w", entryIndex, readErr))
		}
		alias, decodeErr := decodeJavaModifiedUTF8(aliasBytes)
		if decodeErr != nil {
			parseErrors = append(parseErrors, fmt.Errorf("entry %d alias: %w", entryIndex, decodeErr))
			alias = strings.ToValidUTF8(string(aliasBytes), "�")
		}
		if readErr := reader.skip(8); readErr != nil {
			return certificates, errors.Join(errors.Join(parseErrors...), fmt.Errorf("entry %d creation date: %w", entryIndex, readErr))
		}

		switch tag {
		case keystoreTagPrivateKey:
			privateKeyEntries++
			keyLength, readErr := reader.uint32()
			if readErr != nil {
				return certificates, errors.Join(errors.Join(parseErrors...), fmt.Errorf("entry %d private-key length: %w", entryIndex, readErr))
			}
			if readErr := reader.skipUint32(keyLength); readErr != nil {
				return certificates, errors.Join(errors.Join(parseErrors...), fmt.Errorf("entry %d private-key blob: %w", entryIndex, readErr))
			}
			chainLength, readErr := reader.uint32()
			if readErr != nil {
				return certificates, errors.Join(errors.Join(parseErrors...), fmt.Errorf("entry %d chain length: %w", entryIndex, readErr))
			}
			for chainIndex := range chainLength {
				certificate, certificateErr := reader.certificate(version, KeystoreInfo{
					Format:     format,
					Alias:      alias,
					EntryType:  KeystoreEntryPrivateKey,
					ChainIndex: int(chainIndex),
				})
				if certificateErr != nil {
					if certificate == nil {
						return certificates, errors.Join(
							errors.Join(parseErrors...),
							fmt.Errorf("entry %d chain certificate %d: %w", entryIndex, chainIndex, certificateErr),
						)
					}
					parseErrors = append(
						parseErrors,
						fmt.Errorf("entry %d chain certificate %d: %w", entryIndex, chainIndex, certificateErr),
					)
				}
				if certificate != nil && certificate.certificate != nil {
					certificates = append(certificates, *certificate)
				}
			}
		case keystoreTagTrusted:
			trustedEntries++
			certificate, certificateErr := reader.certificate(version, KeystoreInfo{
				Format:     format,
				Alias:      alias,
				EntryType:  KeystoreEntryTrustedCert,
				ChainIndex: 0,
			})
			if certificateErr != nil {
				if certificate == nil {
					return certificates, errors.Join(
						errors.Join(parseErrors...),
						fmt.Errorf("entry %d trusted certificate: %w", entryIndex, certificateErr),
					)
				}
				parseErrors = append(parseErrors, fmt.Errorf("entry %d trusted certificate: %w", entryIndex, certificateErr))
			}
			if certificate != nil && certificate.certificate != nil {
				certificates = append(certificates, *certificate)
			}
		case keystoreTagSecretKey:
			return certificates, errors.Join(
				errors.Join(parseErrors...),
				fmt.Errorf("entry %d is an unsupported JCEKS secret-key entry", entryIndex),
			)
		default:
			return certificates, errors.Join(errors.Join(parseErrors...), fmt.Errorf("entry %d has unsupported tag %d", entryIndex, tag))
		}
	}
	if reader.remaining() != 0 {
		return certificates, errors.Join(
			errors.Join(parseErrors...),
			fmt.Errorf("%s has %d unexpected bytes before the integrity MAC", format, reader.remaining()),
		)
	}
	if len(certificates) == 0 {
		parseErrors = append(parseErrors, fmt.Errorf("%s contains no X.509 certificates", format))
	}
	truststore := privateKeyEntries == 0 && trustedEntries > 0
	for index := range certificates {
		certificates[index].keystore.Truststore = truststore
	}
	return certificates, errors.Join(parseErrors...)
}

func (reader *javaKeystoreReader) certificate(
	version uint32,
	keystore KeystoreInfo,
) (*javaKeystoreCertificate, error) {
	var certificateType string
	if version == 2 {
		encodedType, err := reader.lengthPrefixedUint16()
		if err != nil {
			return nil, fmt.Errorf("certificate type: %w", err)
		}
		certificateType, err = decodeJavaModifiedUTF8(encodedType)
		if err != nil {
			return nil, fmt.Errorf("certificate type: %w", err)
		}
	} else {
		certificateType = javaKeystoreCertificateType
	}
	derLength, err := reader.uint32()
	if err != nil {
		return nil, fmt.Errorf("DER length: %w", err)
	}
	der, err := reader.takeUint32(derLength)
	if err != nil {
		return nil, fmt.Errorf("DER: %w", err)
	}
	if !strings.EqualFold(certificateType, javaKeystoreCertificateType) {
		return &javaKeystoreCertificate{keystore: keystore}, fmt.Errorf("unsupported certificate type %q", certificateType)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return &javaKeystoreCertificate{keystore: keystore}, fmt.Errorf("parse X.509 DER: %w", err)
	}
	return &javaKeystoreCertificate{certificate: parsed, keystore: keystore}, nil
}

func (reader *javaKeystoreReader) uint32() (uint32, error) {
	data, err := reader.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(data), nil
}

func (reader *javaKeystoreReader) lengthPrefixedUint16() ([]byte, error) {
	lengthData, err := reader.take(2)
	if err != nil {
		return nil, err
	}
	return reader.take(int(binary.BigEndian.Uint16(lengthData)))
}

func (reader *javaKeystoreReader) takeUint32(length uint32) ([]byte, error) {
	if int64(length) > int64(reader.remaining()) {
		return nil, io.ErrUnexpectedEOF
	}
	return reader.take(int(length))
}

func (reader *javaKeystoreReader) skipUint32(length uint32) error {
	_, err := reader.takeUint32(length)
	return err
}

func (reader *javaKeystoreReader) skip(length int) error {
	_, err := reader.take(length)
	return err
}

func (reader *javaKeystoreReader) take(length int) ([]byte, error) {
	if length < 0 || length > reader.remaining() {
		return nil, io.ErrUnexpectedEOF
	}
	start := reader.offset
	reader.offset += length
	return reader.data[start:reader.offset], nil
}

func (reader *javaKeystoreReader) remaining() int {
	return len(reader.data) - reader.offset
}

func decodeJavaModifiedUTF8(encoded []byte) (string, error) {
	codeUnits := make([]uint16, 0, len(encoded))
	for offset := 0; offset < len(encoded); {
		first := encoded[offset]
		switch {
		case first >= 0x01 && first <= 0x7f:
			codeUnits = append(codeUnits, uint16(first))
			offset++
		case first&0xe0 == 0xc0:
			if offset+1 >= len(encoded) || encoded[offset+1]&0xc0 != 0x80 {
				return "", fmt.Errorf("invalid two-byte sequence at offset %d", offset)
			}
			value := uint16(first&0x1f)<<6 | uint16(encoded[offset+1]&0x3f)
			if value != 0 && value < 0x80 {
				return "", fmt.Errorf("overlong two-byte sequence at offset %d", offset)
			}
			if value == 0 && (first != 0xc0 || encoded[offset+1] != 0x80) {
				return "", fmt.Errorf("invalid NUL sequence at offset %d", offset)
			}
			codeUnits = append(codeUnits, value)
			offset += 2
		case first&0xf0 == 0xe0:
			if offset+2 >= len(encoded) || encoded[offset+1]&0xc0 != 0x80 || encoded[offset+2]&0xc0 != 0x80 {
				return "", fmt.Errorf("invalid three-byte sequence at offset %d", offset)
			}
			value := uint16(first&0x0f)<<12 | uint16(encoded[offset+1]&0x3f)<<6 | uint16(encoded[offset+2]&0x3f)
			if value < 0x800 {
				return "", fmt.Errorf("overlong three-byte sequence at offset %d", offset)
			}
			codeUnits = append(codeUnits, value)
			offset += 3
		default:
			return "", fmt.Errorf("invalid leading byte 0x%02x at offset %d", first, offset)
		}
	}

	runes := make([]rune, 0, len(codeUnits))
	for index := 0; index < len(codeUnits); index++ {
		unit := codeUnits[index]
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+1 >= len(codeUnits) || codeUnits[index+1] < 0xdc00 || codeUnits[index+1] > 0xdfff {
				return "", fmt.Errorf("unpaired high surrogate at code unit %d", index)
			}
			runes = append(runes, utf16.DecodeRune(rune(unit), rune(codeUnits[index+1])))
			index++
		case unit >= 0xdc00 && unit <= 0xdfff:
			return "", fmt.Errorf("unpaired low surrogate at code unit %d", index)
		default:
			runes = append(runes, rune(unit))
		}
	}
	return string(runes), nil
}
