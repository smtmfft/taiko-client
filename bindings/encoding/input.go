package encoding

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"

	"github.com/taikoxyz/taiko-client/bindings"
)

// ABI arguments marshaling components.
var (
	blockMetadataComponents = []abi.ArgumentMarshaling{
		{
			Name: "l1Hash",
			Type: "bytes32",
		},
		{
			Name: "difficulty",
			Type: "bytes32",
		},
		{
			Name: "blobHash",
			Type: "bytes32",
		},
		{
			Name: "extraData",
			Type: "bytes32",
		},
		{
			Name: "depositsHash",
			Type: "bytes32",
		},
		{
			Name: "coinbase",
			Type: "address",
		},
		{
			Name: "id",
			Type: "uint64",
		},
		{
			Name: "gasLimit",
			Type: "uint32",
		},
		{
			Name: "timestamp",
			Type: "uint64",
		},
		{
			Name: "l1Height",
			Type: "uint64",
		},
		{
			Name: "txListByteOffset",
			Type: "uint24",
		},
		{
			Name: "txListByteSize",
			Type: "uint24",
		},
		{
			Name: "minTier",
			Type: "uint16",
		},
		{
			Name: "blobUsed",
			Type: "bool",
		},
		{
			Name: "parentMetaHash",
			Type: "bytes32",
		},
	}
	transitionComponents = []abi.ArgumentMarshaling{
		{
			Name: "parentHash",
			Type: "bytes32",
		},
		{
			Name: "blockHash",
			Type: "bytes32",
		},
		{
			Name: "signalRoot",
			Type: "bytes32",
		},
		{
			Name: "graffiti",
			Type: "bytes32",
		},
	}
	tierProofComponents = []abi.ArgumentMarshaling{
		{
			Name: "tier",
			Type: "uint16",
		},
		{
			Name: "data",
			Type: "bytes",
		},
	}
	blockParamsComponents = []abi.ArgumentMarshaling{
		{
			Name: "assignedProver",
			Type: "address",
		},
		{
			Name: "extraData",
			Type: "bytes32",
		},
		{
			Name: "blobHash",
			Type: "bytes32",
		},
		{
			Name: "txListByteOffset",
			Type: "uint24",
		},
		{
			Name: "txListByteSize",
			Type: "uint24",
		},
		{
			Name: "cacheBlobForReuse",
			Type: "bool",
		},
		{
			Name: "parentMetaHash",
			Type: "bytes32",
		},
		{
			Name: "hookCalls",
			Type: "tuple[]",
			Components: []abi.ArgumentMarshaling{
				{
					Name: "hook",
					Type: "address",
				},
				{
					Name: "data",
					Type: "bytes",
				},
			},
		},
	}
	proverAssignmentComponents = []abi.ArgumentMarshaling{
		{
			Name: "feeToken",
			Type: "address",
		},
		{
			Name: "expiry",
			Type: "uint64",
		},
		{
			Name: "maxBlockId",
			Type: "uint64",
		},
		{
			Name: "maxProposedIn",
			Type: "uint64",
		},
		{
			Name: "metaHash",
			Type: "bytes32",
		},
		{
			Name: "parentMetaHash",
			Type: "bytes32",
		},
		{
			Name: "tierFees",
			Type: "tuple[]",
			Components: []abi.ArgumentMarshaling{
				{
					Name: "tier",
					Type: "uint16",
				},
				{
					Name: "fee",
					Type: "uint128",
				},
			},
		},
		{
			Name: "signature",
			Type: "bytes",
		},
	}
	assignmentHookInputComponents = []abi.ArgumentMarshaling{
		{
			Name:       "assignment",
			Type:       "tuple",
			Components: proverAssignmentComponents,
		},
		{
			Name: "tip",
			Type: "uint256",
		},
	}
	zkEvmProofComponents = []abi.ArgumentMarshaling{
		{
			Name: "verifierId",
			Type: "uint16",
		},
		{
			Name: "zkp",
			Type: "bytes",
		},
		{
			Name: "pointProof",
			Type: "bytes",
		},
	}
)

var (
	assignmentHookInputType, _   = abi.NewType("tuple", "AssignmentHook.Input", assignmentHookInputComponents)
	assignmentHookInputArgs      = abi.Arguments{{Name: "AssignmentHook.Input", Type: assignmentHookInputType}}
	zkEvmProofType, _            = abi.NewType("tuple", "ZkEvmProof", zkEvmProofComponents)
	zkEvmProofArgs               = abi.Arguments{{Name: "ZkEvmProof", Type: zkEvmProofType}}
	blockParamsComponentsType, _ = abi.NewType("tuple", "TaikoData.BlockParams", blockParamsComponents)
	blockParamsComponentsArgs    = abi.Arguments{{Name: "TaikoData.BlockParams", Type: blockParamsComponentsType}}
	// ProverAssignmentPayload
	stringType, _   = abi.NewType("string", "", nil)
	bytes32Type, _  = abi.NewType("bytes32", "", nil)
	addressType, _  = abi.NewType("address", "", nil)
	uint64Type, _   = abi.NewType("uint64", "", nil)
	tierFeesType, _ = abi.NewType(
		"tuple[]",
		"",
		[]abi.ArgumentMarshaling{
			{
				Name: "tier",
				Type: "uint16",
			},
			{
				Name: "fee",
				Type: "uint128",
			},
		},
	)
	proverAssignmentPayloadArgs = abi.Arguments{
		{Name: "PROVER_ASSIGNMENT", Type: stringType},
		{Name: "chainID", Type: uint64Type},
		{Name: "taikoAddress", Type: addressType},
		{Name: "assignmentHookAddress", Type: addressType},
		{Name: "metaHash", Type: bytes32Type},
		{Name: "parentMetaHash", Type: bytes32Type},
		{Name: "blobHash", Type: bytes32Type},
		{Name: "assignment.feeToken", Type: addressType},
		{Name: "assignment.expiry", Type: uint64Type},
		{Name: "assignment.maxBlockId", Type: uint64Type},
		{Name: "assignment.maxProposedIn", Type: uint64Type},
		{Name: "assignment.tierFees", Type: tierFeesType},
	}
	blockMetadataComponentsType, _ = abi.NewType("tuple", "TaikoData.BlockMetadata", blockMetadataComponents)
	transitionComponentsType, _    = abi.NewType("tuple", "TaikoData.Transition", transitionComponents)
	tierProofComponentsType, _     = abi.NewType("tuple", "TaikoData.TierProof", tierProofComponents)
	proveBlockInputArgs            = abi.Arguments{
		{Name: "TaikoData.BlockMetadata", Type: blockMetadataComponentsType},
		{Name: "TaikoData.Transition", Type: transitionComponentsType},
		{Name: "TaikoData.TierProof", Type: tierProofComponentsType},
	}
)

// Sgx ABIs
var (
	V3QuoteHeaderAugment = []abi.ArgumentMarshaling{
		{
			Name: "version",
			Type: "bytes2",
		},
		{
			Name: "attestationKeyType",
			Type: "bytes2",
		},
		{
			Name: "teeType",
			Type: "bytes4",
		},
		{
			Name: "qeSvn",
			Type: "bytes2",
		},
		{
			Name: "pceSvn",
			Type: "bytes2",
		},
		{
			Name: "qeVendorId",
			Type: "bytes16",
		},
		{
			Name: "userData",
			Type: "bytes20",
		},
	}
	V3QuoteEnclaveReport = []abi.ArgumentMarshaling{
		{
			Name: "cpuSvn",
			Type: "bytes16",
		},
		{
			Name: "miscSelect",
			Type: "bytes4",
		},
		{
			Name: "reserved1",
			Type: "bytes28",
		},
		{
			Name: "attributes",
			Type: "bytes16",
		},
		{
			Name: "mrEnclave",
			Type: "bytes32",
		},
		{
			Name: "reserved2",
			Type: "bytes32",
		},
		{
			Name: "mrSigner",
			Type: "bytes32",
		},
		{
			Name: "reserved3",
			Type: "bytes",
		},
		{
			Name: "isvProdId",
			Type: "uint16",
		},
		{
			Name: "isvSvn",
			Type: "uint16",
		},
		{
			Name: "reserved4",
			Type: "bytes",
		},
		{
			Name: "reportData",
			Type: "bytes",
		},
	}
	V3ParsedQEAuthData = []abi.ArgumentMarshaling{
		{
			Name: "parsedDataSize",
			Type: "uint16",
		},
		{
			Name: "data",
			Type: "bytes",
		},
	}
	V3ParsedCertificationData = []abi.ArgumentMarshaling{
		{
			Name: "certType",
			Type: "uint16",
		},
		{
			Name: "certDataSize",
			Type: "uint32",
		},
		{
			Name: "decodedCertDataArray",
			Type: "bytes[3]",
		},
	}
	V3ParsedECDSAQuoteV3AuthData = []abi.ArgumentMarshaling{
		{
			Name: "ecdsa256BitSignature",
			Type: "bytes",
		},
		{
			Name: "ecdsaAttestationKey",
			Type: "bytes",
		},
		{
			Name:       "pckSignedQeReport",
			Type:       "tuple",
			Components: V3QuoteEnclaveReport,
		},
		{
			Name: "qeReportSignature",
			Type: "bytes",
		},
		{
			Name:       "qeAuthData",
			Type:       "tuple",
			Components: V3ParsedQEAuthData,
		},
		{
			Name:       "certification",
			Type:       "tuple",
			Components: V3ParsedCertificationData,
		},
	}
	V3ParsedQuoteStruct = []abi.ArgumentMarshaling{
		{
			Name:       "header",
			Type:       "tuple",
			Components: V3QuoteHeaderAugment,
		},
		{
			Name:       "localEnclaveReport",
			Type:       "tuple",
			Components: V3QuoteEnclaveReport,
		},
		{
			Name:       "v3AuthData",
			Type:       "tuple",
			Components: V3ParsedECDSAQuoteV3AuthData,
		},
	}

	ParsedV3QuoteStruct, _ = abi.NewType("tuple", "struct ParsedV3QuoteStruct", V3ParsedQuoteStruct)

	ParsedV3QuoteStructArgs = abi.Arguments{
		{Type: ParsedV3QuoteStruct, Name: "ParsedV3QuoteStruct"},
	}
)

// Contract ABIs.
var (
	TaikoL1ABI        *abi.ABI
	TaikoL2ABI        *abi.ABI
	AssignmentHookABI *abi.ABI
)

func init() {
	var err error

	if TaikoL1ABI, err = bindings.TaikoL1ClientMetaData.GetAbi(); err != nil {
		log.Crit("Get TaikoL1 ABI error", "error", err)
	}

	if TaikoL2ABI, err = bindings.TaikoL2ClientMetaData.GetAbi(); err != nil {
		log.Crit("Get TaikoL2 ABI error", "error", err)
	}

	if AssignmentHookABI, err = bindings.AssignmentHookMetaData.GetAbi(); err != nil {
		log.Crit("Get AssignmentHook ABI error", "error", err)
	}
}

// EncodeBlockParams performs the solidity `abi.encode` for the given blockParams.
func EncodeBlockParams(params *BlockParams) ([]byte, error) {
	b, err := blockParamsComponentsArgs.Pack(params)
	if err != nil {
		return nil, fmt.Errorf("failed to abi.encode block params, %w", err)
	}
	return b, nil
}

// EncodeBlockParams performs the solidity `abi.encode` for the given blockParams.
func EncodeZKEvmProof(proof []byte) ([]byte, error) {
	b, err := zkEvmProofArgs.Pack(&ZKEvmProof{
		VerifierId: 0,
		Zkp:        proof,
		PointProof: []byte{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to abi.encode ZkEvmProof, %w", err)
	}
	return b, nil
}

// EncodeBlockParams performs the solidity `abi.encode` for the given blockParams.
func EncodeSgxQuoteProof(proof []byte) ([]byte, error) {
	// 	SgxQuote TaikoDataParsedV3QuoteStruct
	quote, err := generateSgxQuote(proof);

	b, err := ParsedV3QuoteStructArgs.Pack(*quote);
	if err != nil {
		return nil, fmt.Errorf("failed to abi.encode ZkEvmProof, %w", err)
	}
	return b, nil
}

// EncodeAssignmentHookInput performs the solidity `abi.encode` for the given input
func EncodeAssignmentHookInput(input *AssignmentHookInput) ([]byte, error) {
	b, err := assignmentHookInputArgs.Pack(input)
	if err != nil {
		return nil, fmt.Errorf("failed to abi.encode assignment hook input params, %w", err)
	}
	return b, nil
}

// EncodeProverAssignmentPayload performs the solidity `abi.encode` for the given proverAssignment payload.
func EncodeProverAssignmentPayload(
	chainID uint64,
	taikoAddress common.Address,
	assignmentHookAddress common.Address,
	txListHash common.Hash,
	feeToken common.Address,
	expiry uint64,
	maxBlockID uint64,
	maxProposedIn uint64,
	tierFees []TierFee,
) ([]byte, error) {
	b, err := proverAssignmentPayloadArgs.Pack(
		"PROVER_ASSIGNMENT",
		chainID,
		taikoAddress,
		assignmentHookAddress,
		common.Hash{},
		common.Hash{},
		txListHash,
		feeToken,
		expiry,
		maxBlockID,
		maxProposedIn,
		tierFees,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to abi.encode prover assignment hash payload, %w", err)
	}
	return b, nil
}

// EncodeProveBlockInput performs the solidity `abi.encode` for the given TaikoL1.proveBlock input.
func EncodeProveBlockInput(
	meta *bindings.TaikoDataBlockMetadata,
	transition *bindings.TaikoDataTransition,
	tierProof *bindings.TaikoDataTierProof,
) ([]byte, error) {
	b, err := proveBlockInputArgs.Pack(meta, transition, tierProof)
	if err != nil {
		return nil, fmt.Errorf("failed to abi.encode TakoL1.proveBlock input, %w", err)
	}
	return b, nil
}

// UnpackTxListBytes unpacks the input data of a TaikoL1.proposeBlock transaction, and returns the txList bytes.
func UnpackTxListBytes(txData []byte) ([]byte, error) {
	method, err := TaikoL1ABI.MethodById(txData)
	if err != nil {
		return nil, err
	}

	// Only check for safety.
	if method.Name != "proposeBlock" {
		return nil, fmt.Errorf("invalid method name: %s", method.Name)
	}

	args := map[string]interface{}{}

	if err := method.Inputs.UnpackIntoMap(args, txData[4:]); err != nil {
		return nil, err
	}

	inputs, ok := args["txList"].([]byte)

	if !ok {
		return nil, errors.New("failed to get txList bytes")
	}

	return inputs, nil
}

func generateSgxQuote(proof []byte) (*bindings.TaikoDataParsedV3QuoteStruct, error) {
	sgxQuote := bindings.TaikoDataParsedV3QuoteStruct{
		Header: bindings.TaikoDataHeader{
			Version:            [2]byte{0},
			AttestationKeyType: [2]byte{0},
			TeeType:            [4]byte{0},
			QeSvn:              [2]byte{0},
			PceSvn:             [2]byte{0},
			QeVendorId:         [16]byte{0},
			UserData:           [20]byte{0},
		},
		LocalEnclaveReport: bindings.TaikoDataEnclaveReport{
			CpuSvn:     [16]byte{0},
			MiscSelect: [4]byte{0},
			Reserved1:  [28]byte{0},
			Attributes: [16]byte{0},
			MrEnclave:  [32]byte{0},
			Reserved2:  [32]byte{0},
			MrSigner:   [32]byte{0},
			Reserved3:  make([]byte, 96),
			IsvProdId:  0,
			IsvSvn:     0,
			Reserved4:  make([]byte, 60),
			ReportData: make([]byte, 64),
		},
		V3AuthData: bindings.TaikoDataParsedECDSAQuoteV3AuthData{
			Ecdsa256BitSignature: make([]byte, 64),
			EcdsaAttestationKey:  make([]byte, 64),
			PckSignedQeReport: bindings.TaikoDataEnclaveReport{
				CpuSvn:     [16]byte{0},
				MiscSelect: [4]byte{0},
				Reserved1:  [28]byte{0},
				Attributes: [16]byte{0},
				MrEnclave:  [32]byte{0},
				Reserved2:  [32]byte{0},
				MrSigner:   [32]byte{0},
				Reserved3:  make([]byte, 96),
				IsvProdId:  0,
				IsvSvn:     0,
				Reserved4:  make([]byte, 60),
				ReportData: make([]byte, 64),
			},
			QeReportSignature: make([]byte, 64),
			QeAuthData: bindings.TaikoDataParsedQEAuthData{
				ParsedDataSize: 0,
				Data:           make([]byte, 0),
			},
			Certification: bindings.TaikoDataParsedCertificationData{
				CertType:     0,
				CertDataSize: 0,
				DecodedCertDataArray: [3][]byte{
					{},
					{},
					{},
				},
			},
		},
	}

	err := fillSgxQuote(proof, &sgxQuote);
	if err != nil {
		return nil, err
	}
	return &sgxQuote, nil
}

func fillSgxQuote(proof []byte, sgxQuote *bindings.TaikoDataParsedV3QuoteStruct) error {
    quoteBytes := proof;
    header := quoteBytes[0:48];
    localQeReport := quoteBytes[48:48 + 384];
	v3AuthDataSize := binary.LittleEndian.Uint32(quoteBytes[48 + 384:48 + 384 + 4]);
    v3AuthData := quoteBytes[48 + 384 + 4:]
	// assert(v3AuthDataSize == v3AuthData.length, "v3AuthDataSize != v3AuthData.length");
	if int64(v3AuthDataSize) != int64(len(v3AuthData)) {
		return errors.New("v3AuthDataSize != v3AuthData.length")
	}

    err, v3ParsedAuthData := parseV3AuthData(v3AuthData);
	if err != nil {
		return err
	}

	parsedV3Quote := bindings.TaikoDataParsedV3QuoteStruct{
        Header: bindings.TaikoDataHeader {
            Version: *(*[2]byte)(header[0:2]),
            AttestationKeyType: *(*[2]byte)(header[2:2 + 2]),
            TeeType: *(*[4]byte)(header[4:4 + 4]),
            QeSvn: *(*[2]byte)(header[8:8 + 2]),
            PceSvn: *(*[2]byte)(header[10:10 + 2]),
            QeVendorId: *(*[16]byte)(header[12:12 + 16]),
            UserData: *(*[20]byte)(header[28:28 + 20]),
        },
        LocalEnclaveReport: bindings.TaikoDataEnclaveReport {
            CpuSvn: *(*[16]byte)(localQeReport[0:0 + 16]),
            MiscSelect: *(*[4]byte)(localQeReport[16:16 + 4]),
            Reserved1: *(*[28]byte)(localQeReport[20:20 + 28]),
            Attributes: *(*[16]byte)(localQeReport[48:48 + 16]),
            MrEnclave: *(*[32]byte)(localQeReport[64:64 + 32]),
            Reserved2: *(*[32]byte)(localQeReport[96:96 + 32]),
            MrSigner:  *(*[32]byte)(localQeReport[128:128 + 32]),
            Reserved3: localQeReport[160:160 + 96],
            IsvProdId: binary.LittleEndian.Uint16(localQeReport[256:256 + 2]),
            IsvSvn: binary.LittleEndian.Uint16(localQeReport[258:258 + 2]),
            Reserved4:  localQeReport[260:260 + 60],
            ReportData: localQeReport[320:320 + 64],
        },
        V3AuthData: v3ParsedAuthData,
    };
    *sgxQuote = parsedV3Quote
	return nil
}

func parseV3AuthData(v3AuthData []byte) (error, bindings.TaikoDataParsedECDSAQuoteV3AuthData) {
	pckSignedQeReport := v3AuthData[128:128 + 384];
    log.Debug("Buffer.from(v3AuthData[576:576 + 2]).readUint16LE()", v3AuthData[576:576 + 2]);
    parsedDataSize := binary.LittleEndian.Uint16(v3AuthData[576:576 + 2]);
    certDataOffset := 578 + parsedDataSize;
    log.Debug("Buffer.from(v3AuthData.slice(%s, certDataOffset + 2)) = ", certDataOffset, v3AuthData[certDataOffset:certDataOffset + 2]);
    parsedCertType := binary.LittleEndian.Uint16(v3AuthData[certDataOffset: certDataOffset + 2]);
    parsedCertDataSize :=binary.LittleEndian.Uint32(v3AuthData[certDataOffset + 2: certDataOffset + 2 + 4]);
    // assert(certDataOffset + 2 + 4 + parsedCertDataSize == v3AuthData.length, "certDataOffset+2+4+parsedCertDataSize != v3AuthData.length");
	if uint64(uint32(certDataOffset) + 2 + 4 + parsedCertDataSize) != uint64(len(v3AuthData)) {
		return errors.New("certDataOffset+2+4+parsedCertDataSize != v3AuthData.length"), bindings.TaikoDataParsedECDSAQuoteV3AuthData{}
	}

    err, decodedCertDataArray := splitCert(v3AuthData[certDataOffset + 2 + 4:]);
    return err, bindings.TaikoDataParsedECDSAQuoteV3AuthData{
        Ecdsa256BitSignature: v3AuthData[0:0 + 64],
        EcdsaAttestationKey: v3AuthData[64:64 + 64],
        PckSignedQeReport: bindings.TaikoDataEnclaveReport {
            CpuSvn: *(*[16]byte)(pckSignedQeReport[0:0 + 16]),
            MiscSelect: *(*[4]byte)(pckSignedQeReport[16:16 + 4]),
            Reserved1: *(*[28]byte)(pckSignedQeReport[20:20 + 28]),
            Attributes: *(*[16]byte)(pckSignedQeReport[48:48 + 16]),
            MrEnclave: *(*[32]byte)(pckSignedQeReport[64:64 + 32]),
            Reserved2: *(*[32]byte)(pckSignedQeReport[96:96 + 32]),
            MrSigner:  *(*[32]byte)(pckSignedQeReport[128:128 + 32]),
            Reserved3: pckSignedQeReport[160:160 + 96],
            IsvProdId: binary.LittleEndian.Uint16(pckSignedQeReport[256:256 + 2]),
            IsvSvn: binary.LittleEndian.Uint16(pckSignedQeReport[258:258 + 2]),
            Reserved4:  pckSignedQeReport[260:260 + 60],
            ReportData: pckSignedQeReport[320:320 + 64],
        },
        QeReportSignature: v3AuthData[512:512 + 64],
        QeAuthData: bindings.TaikoDataParsedQEAuthData {
            ParsedDataSize: parsedDataSize,
            Data: v3AuthData[578: 578 + parsedDataSize],
        },
        Certification: bindings.TaikoDataParsedCertificationData {
            CertType: parsedCertType,
            CertDataSize: parsedCertDataSize,
            DecodedCertDataArray: decodedCertDataArray,
        },
    };
}

func splitCert(certChainBytes []byte) (error, [3][]byte) {
		pattern := "^-----BEGIN CERTIFICATE-----\r?\n((?:(?!-----).*\r?\n)*)-----END CERTIFICATE-----";
		regex := regexp.MustCompile(pattern);
		certText := string(certChainBytes[:]);
		log.Debug("cert str = %s", certText);

		certs := regex.FindAll(certChainBytes, -1);
		if len(certs) != 3 {
			return fmt.Errorf("certs.length != 3"), [3][]byte{}
		}

		i := 1;
		certChain := make([][]byte, 3)
		for _, cert := range certs {
			rawDecodedText, err := base64.StdEncoding.DecodeString(string(cert[:]));
			if err != nil {
				return err, [3][]byte{}
			}
			certChain[i] = rawDecodedText;
			i += 1;
		}
		return nil, *(*[3][]byte)(certChain);
}