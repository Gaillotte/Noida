"""KMIP enumerations — values match the OASIS TTLV specification."""
from enum import IntEnum


class Tag(IntEnum):
    """Codepoints verified against the OASIS KMIP 2.1 tag registry (cross-checked
    via PyKMIP's kmip/core/enums.py, itself derived from the spec)."""

    # Structure tags
    RequestMessage          = 0x420078
    ResponseMessage         = 0x42007B
    RequestHeader           = 0x420077
    ResponseHeader          = 0x42007A
    RequestPayload          = 0x420079
    ResponsePayload         = 0x42007C
    BatchItem               = 0x42000F
    BatchCount              = 0x42000D
    Authentication          = 0x42000C
    Credential              = 0x420023
    CredentialType          = 0x420024
    CredentialValue         = 0x420025
    Username                = 0x420099
    Password                = 0x4200A1

    # Protocol
    ProtocolVersion         = 0x420069
    ProtocolVersionMajor    = 0x42006A
    ProtocolVersionMinor    = 0x42006B
    Operation               = 0x42005C
    UniqueIdentifier        = 0x420094
    ResultStatus            = 0x42007F
    ResultReason            = 0x42007E
    ResultMessage           = 0x42007D

    # Object / attribute tags
    ObjectType              = 0x420057
    # Real KMIP has no generic "ManagedObject" wrapper — Get responses are
    # wrapped in the specific object type's own tag.
    SymmetricKey            = 0x42008F
    PrivateKey              = 0x420064
    PublicKey               = 0x42006D
    SplitKey                = 0x420089
    SecretData              = 0x420085
    Attributes              = 0x420125  # v2.0+
    Attribute               = 0x420008
    AttributeName           = 0x42000A
    AttributeValue          = 0x42000B
    AttributeIndex          = 0x420009
    Name                    = 0x420053
    NameValue               = 0x420055
    NameType                = 0x420054
    CryptographicAlgorithm  = 0x420028
    CryptographicLength     = 0x42002A
    CryptographicUsageMask  = 0x42002C
    CryptographicParameters = 0x42002B
    State                   = 0x42008D
    InitialDate             = 0x420039
    ActivationDate          = 0x420001
    DeactivationDate        = 0x42002F
    DestroyDate             = 0x420033
    CompromiseOccurrenceDate= 0x420021
    RevocationReason        = 0x420081
    RevocationMessage       = 0x420080
    Link                    = 0x42004A
    LinkType                = 0x42004B
    LinkedObjectIdentifier  = 0x42004C
    ApplicationSpecificInformation = 0x420004
    ApplicationNamespace    = 0x420003
    ApplicationData         = 0x420002
    Sensitive               = 0x420120
    AlwaysSensitive         = 0x420121
    Extractable             = 0x420122
    NeverExtractable        = 0x420123

    # Key structures
    KeyBlock                = 0x420040
    KeyFormatType           = 0x420042
    KeyValue                = 0x420045
    KeyMaterial             = 0x420043
    KeyCompressionType      = 0x420041
    WrappingMethod          = 0x42009E
    KeyWrappingData         = 0x420046
    KeyWrappingSpecification= 0x420047
    EncryptionKeyInformation= 0x420036
    MACDataKeyInformation   = 0x42004E  # real name: MAC/Signature Key Information

    # Certificate
    Certificate             = 0x420013
    CertificateType         = 0x42001D
    CertificateValue        = 0x42001E
    CertificateIdentifier   = 0x420014
    CertificateIssuer       = 0x420015
    CertificateSubject      = 0x42001A
    SubjectDistinguishedName= 0x4200B4

    # Crypto request/response
    Data                    = 0x4200C2
    DataLength              = 0x4200C4
    IVCounterNonce          = 0x42003D
    InitIndicator           = 0x4200D7
    FinalIndicator          = 0x4200D8
    AuthenticatedEncryptionAdditionalData = 0x4200FE
    AuthenticatedEncryptionTag = 0x4200FF
    CryptographicParameters_BlockCipherMode = 0x420011  # real name: Block Cipher Mode
    PaddingMethod           = 0x42005F
    HashingAlgorithm        = 0x420038
    KeyRoleType             = 0x420083
    SignatureData           = 0x4200C3  # real name: Signature Data
    ValidityIndicator       = 0x42009B
    MACData                 = 0x42004D  # real name: MAC/Signature

    # EC / DSA domain parameters
    CryptographicDomainParameters = 0x420029
    RecommendedCurve        = 0x420075
    QLength                 = 0x420073

    # Import / Export (v2.0+)
    ReplaceExisting         = 0x420124

    # Operation payloads
    TemplateAttribute       = 0x420091
    CommonAttributes        = 0x420126
    PrivateKeyAttributes    = 0x420127
    PublicKeyAttributes     = 0x420128

    # Query
    QueryFunction           = 0x420074
    Operations              = 0x42014F  # distinct from Operation (request field)
    ServerInformation       = 0x420088
    VendorIdentification    = 0x42009D

    # Locate
    MaximumItems            = 0x42004F
    StorageStatusMask       = 0x42008E

    # Revoke
    RevocationReasonCode    = 0x420082

    # Re-key
    Offset                  = 0x420058

    # Batch
    UniqueBatchItemID       = 0x420093
    AsynchronousIndicator   = 0x420007
    AsynchronousCorrelationValue = 0x420006
    BatchErrorContinuationOption = 0x42000E
    BatchOrderOption        = 0x420010
    MaximumResponseSize     = 0x420050

    # AdjustAttribute
    AdjustmentType          = 0x420158

    # DeriveKey
    DerivationMethod        = 0x420031
    DerivationParameters    = 0x420032
    DerivationData          = 0x420030

    # ObtainLease / GetUsageAllocation
    LeaseTime               = 0x420049
    LastChangeDate          = 0x420048
    UsageLimitsCount        = 0x420096

    # CreateSplitKey / JoinSplitKey
    SplitKeyParts            = 0x42008B
    SplitKeyThreshold        = 0x42008C
    SplitKeyMethod           = 0x42008A


class Type(IntEnum):
    Structure    = 0x01
    TextString   = 0x02
    ByteString   = 0x03
    Integer      = 0x04
    LongInteger  = 0x05
    BigInteger   = 0x06
    Enumeration  = 0x07
    Boolean      = 0x08
    DateTime     = 0x09
    Interval     = 0x0A
    DateTimeExtended = 0x0B


class ObjectType(IntEnum):
    Certificate  = 0x00000001
    SymmetricKey = 0x00000002
    PublicKey    = 0x00000003
    PrivateKey   = 0x00000004
    SplitKey     = 0x00000005
    Template     = 0x00000006  # deprecated v2.0
    SecretData   = 0x00000007
    OpaqueObject = 0x00000008
    PGPKey       = 0x00000009


class Operation(IntEnum):
    Create              = 0x00000001
    CreateKeyPair       = 0x00000002
    Register            = 0x00000003
    ReKey               = 0x00000004
    DeriveKey           = 0x00000005
    Certify             = 0x00000006
    ReCertify           = 0x00000007
    Locate              = 0x00000008
    Check               = 0x00000009
    Get                 = 0x0000000A
    GetAttributes       = 0x0000000B
    GetAttributeList    = 0x0000000C
    AddAttribute        = 0x0000000D
    ModifyAttribute     = 0x0000000E
    DeleteAttribute     = 0x0000000F
    ObtainLease         = 0x00000010
    GetUsageAllocation  = 0x00000011
    Activate            = 0x00000012
    Revoke              = 0x00000013
    Destroy             = 0x00000014
    Archive             = 0x00000015
    Recover             = 0x00000016
    Validate            = 0x00000017
    Query               = 0x00000018
    Cancel              = 0x00000019
    Poll                = 0x0000001A
    Notify              = 0x0000001B
    Put                 = 0x0000001C
    ReKeyKeyPair        = 0x0000001D
    DiscoverVersions    = 0x0000001E
    Encrypt             = 0x0000001F
    Decrypt             = 0x00000020
    Sign                = 0x00000021
    SignatureVerify     = 0x00000022
    MAC                 = 0x00000023
    MACVerify           = 0x00000024
    RNGRetrieve         = 0x00000025
    RNGSeed             = 0x00000026
    Hash                = 0x00000027
    CreateSplitKey      = 0x00000028
    JoinSplitKey        = 0x00000029
    Import              = 0x0000002A  # v2.0+
    Export              = 0x0000002B  # v2.0+
    Log                 = 0x0000002C
    Login               = 0x0000002D
    Logout              = 0x0000002E
    DelegatedLogin      = 0x0000002F
    AdjustAttribute     = 0x00000030
    SetAttribute        = 0x00000031  # v2.0+
    SetEndpointRole     = 0x00000032
    PKCS11              = 0x00000033
    Interop             = 0x00000034
    ReProvision         = 0x00000035


class ResultStatus(IntEnum):
    Success              = 0x00000000
    OperationFailed      = 0x00000001
    OperationPending     = 0x00000002
    OperationUndone      = 0x00000003


class ResultReason(IntEnum):
    """Codepoints verified against PyKMIP's ResultReason table (same reference
    used to correct Tag in Phase 9); only the subset this server actually
    raises is kept, plus a couple of plausible near-term additions."""
    ItemNotFound                    = 0x00000001
    ResponseTooLarge                = 0x00000002
    AuthenticationNotSuccessful     = 0x00000003
    InvalidMessage                  = 0x00000004
    OperationNotSupported           = 0x00000005
    MissingData                     = 0x00000006
    InvalidField                    = 0x00000007
    FeatureNotSupported             = 0x00000008
    OperationCancelledByRequester   = 0x00000009
    CryptographicFailure            = 0x0000000A
    IllegalOperation                = 0x0000000B
    PermissionDenied                = 0x0000000C
    ObjectArchived                  = 0x0000000D
    IndexOutOfBounds                = 0x0000000E
    KeyValueNotPresent              = 0x00000013
    NotExtractable                  = 0x00000017
    InvalidCSR                      = 0x0000002F
    GeneralFailure                  = 0x00000100


class CryptographicAlgorithm(IntEnum):
    DES         = 0x00000001
    TDES        = 0x00000002
    AES         = 0x00000003
    RSA         = 0x00000004
    DSA         = 0x00000005
    ECDSA       = 0x00000006
    HMACSHA1    = 0x00000007
    HMACSHA224  = 0x00000008
    HMACSHA256  = 0x00000009
    HMACSHA384  = 0x0000000A
    HMACSHA512  = 0x0000000B
    HMACMD5     = 0x0000000C
    DH          = 0x0000000D
    ECDH        = 0x0000000E
    ECMQV       = 0x0000000F
    Blowfish    = 0x00000010
    Camellia    = 0x00000011
    CAST5       = 0x00000012
    IDEA        = 0x00000013
    MARS        = 0x00000014
    RC2         = 0x00000015
    RC4         = 0x00000016
    RC5         = 0x00000017
    SKIPJACK    = 0x00000018
    Twofish     = 0x00000019
    EC          = 0x0000001A
    OneTimePad  = 0x0000001B
    ChaCha20    = 0x0000001C
    Poly1305    = 0x0000001D
    ChaCha20Poly1305 = 0x0000001E
    SHA3224     = 0x0000001F
    SHA3256     = 0x00000020
    SHA3384     = 0x00000021
    SHA3512     = 0x00000022
    HMACSHA3224 = 0x00000023
    HMACSHA3256 = 0x00000024
    HMACSHA3384 = 0x00000025
    HMACSHA3512 = 0x00000026
    SHAKE128    = 0x00000027
    SHAKE256    = 0x00000028


class KeyFormatType(IntEnum):
    Raw                     = 0x00000001
    Opaque                  = 0x00000002
    PKCS1                   = 0x00000003
    PKCS8                   = 0x00000004
    X509                    = 0x00000005
    ECPrivateKey            = 0x00000006
    TransparentSymmetricKey = 0x00000007
    TransparentDSAPrivateKey= 0x00000008
    TransparentDSAPublicKey = 0x00000009
    TransparentRSAPrivateKey= 0x0000000A
    TransparentRSAPublicKey = 0x0000000B
    TransparentDHPrivateKey = 0x0000000C
    TransparentDHPublicKey  = 0x0000000D
    TransparentECDSAPrivateKey = 0x0000000E
    TransparentECDSAPublicKey  = 0x0000000F
    TransparentECDHPrivateKey  = 0x00000010
    TransparentECDHPublicKey   = 0x00000011
    TransparentECMQVPrivateKey = 0x00000012
    TransparentECMQVPublicKey  = 0x00000013
    TransparentECPrivateKey    = 0x00000014
    TransparentECPublicKey     = 0x00000015
    PKCS12                  = 0x00000016
    PKCS10                  = 0x00000017


class State(IntEnum):
    PreActive           = 0x00000001
    Active              = 0x00000002
    Deactivated         = 0x00000003
    Compromised         = 0x00000004
    Destroyed           = 0x00000005
    DestroyedCompromised= 0x00000006


class RevocationReasonCode(IntEnum):
    Unspecified             = 0x00000001
    KeyCompromise           = 0x00000002
    CACompromise            = 0x00000003
    AffiliationChanged      = 0x00000004
    Superseded              = 0x00000005
    CessationOfOperation    = 0x00000006
    PrivilegeWithdrawn      = 0x00000007


class CryptographicUsageMask(IntEnum):
    Sign                = 0x00000001
    Verify              = 0x00000002
    Encrypt             = 0x00000004
    Decrypt             = 0x00000008
    WrapKey             = 0x00000010
    UnwrapKey           = 0x00000020
    Export              = 0x00000040
    MACGenerate         = 0x00000080
    MACVerify           = 0x00000100
    DeriveKey           = 0x00000200
    ContentCommitment   = 0x00000400
    KeyAgreement        = 0x00000800
    CertificateSign     = 0x00001000
    CRLSign             = 0x00002000
    GenerateCryptogram  = 0x00004000
    ValidateCryptogram  = 0x00008000
    TranslateEncrypt    = 0x00010000
    TranslateDecrypt    = 0x00020000
    TranslateWrap       = 0x00040000
    TranslateUnwrap     = 0x00080000


class BlockCipherMode(IntEnum):
    CBC     = 0x00000001
    ECB     = 0x00000002
    PCBC    = 0x00000003
    CFB     = 0x00000004
    OFB     = 0x00000005
    CTR     = 0x00000006
    CMAC    = 0x00000007
    CCM     = 0x00000008
    GCM     = 0x00000009
    CBC_MAC = 0x0000000A
    XTS     = 0x0000000B
    AESKeyWrapPadding = 0x0000000C
    NISTKeyWrap       = 0x0000000D
    X9_102_AESKW      = 0x0000000E
    X9_102_TDKW       = 0x0000000F
    X9_102_AKW1       = 0x00000010
    X9_102_AKW2       = 0x00000011
    AEAD              = 0x00000012


class QueryFunction(IntEnum):
    QueryOperations         = 0x00000001
    QueryObjects            = 0x00000002
    QueryServerInformation  = 0x00000003
    QueryApplicationNamespaces = 0x00000004
    QueryExtensionList      = 0x00000005
    QueryExtensionMap       = 0x00000006
    QueryAttestationTypes   = 0x00000007
    QueryRNGs               = 0x00000008
    QueryValidations        = 0x00000009
    QueryProfiles           = 0x0000000A
    QueryCapabilities       = 0x0000000B
    QueryClientRegistrationMethods = 0x0000000C


class AdjustmentType(IntEnum):
    Increment = 0x00000001
    Decrement = 0x00000002
    Set       = 0x00000003


class RecommendedCurve(IntEnum):
    P_192     = 0x00000001
    P_224     = 0x00000004
    P_256     = 0x00000007
    P_384     = 0x0000000A
    P_521     = 0x0000000D
    SECP256K1 = 0x00000019


class DerivationMethod(IntEnum):
    PBKDF2          = 0x00000001
    HASH            = 0x00000002
    HMAC            = 0x00000003
    ENCRYPT         = 0x00000004
    NIST800_108_C   = 0x00000005
    NIST800_108_F   = 0x00000006
    NIST800_108_DPI = 0x00000007
    ASYMMETRIC_KEY  = 0x00000008


class SplitKeyMethod(IntEnum):
    XOR                       = 0x00000001
    PolynomialSharePrimeField = 0x00000002
    PolynomialShareGF216      = 0x00000003


class WrappingMethod(IntEnum):
    Encrypt               = 0x00000001
    MACSign               = 0x00000002
    Encrypt_then_MACSign   = 0x00000003
    MACSign_then_Encrypt   = 0x00000004
    TR31                   = 0x00000005


class BatchErrorContinuationOption(IntEnum):
    Continue = 0x00000001
    Stop     = 0x00000002
    Undo     = 0x00000003


class NameType(IntEnum):
    UninterpretedTextString = 0x00000001
    URI                     = 0x00000002


class CertificateType(IntEnum):
    X509    = 0x00000001
    PGP     = 0x00000002


class CredentialType(IntEnum):
    UsernameAndPassword  = 0x00000001
    Device               = 0x00000002
    Attestation          = 0x00000003
    OneTimePassword      = 0x00000004
    HashedPassword       = 0x00000005
    Ticket               = 0x00000006


class HashingAlgorithm(IntEnum):
    MD2        = 0x00000001
    MD4        = 0x00000002
    MD5        = 0x00000003
    SHA_1      = 0x00000004
    SHA_224    = 0x00000005
    SHA_256    = 0x00000006
    SHA_384    = 0x00000007
    SHA_512    = 0x00000008
    RIPEMD_160 = 0x00000009
    SHA3_224   = 0x0000000E
    SHA3_256   = 0x0000000F
    SHA3_384   = 0x00000010
    SHA3_512   = 0x00000011


class ValidityIndicator(IntEnum):
    Valid   = 0x00000001
    Invalid = 0x00000002
    Unknown = 0x00000003
