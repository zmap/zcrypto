// Created by extended_key_usage_gen; DO NOT EDIT

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/asn1"
)

const (
OID_EKU_APPLE_CODE_SIGNING = "1.2.840.113635.100.4.1"
OID_EKU_APPLE_CRYPTO_ENV = "1.2.840.113635.100.4.5"
OID_EKU_MICROSOFT_SYSTEM_HEALTH_LOOPHOLE = "1.3.6.1.4.1.311.47.1.3"
OID_EKU_ANY = "2.5.29.37.0"
OID_EKU_APPLE_CRYPTO_MAINTENANCE_ENV = "1.2.840.113635.100.4.5.2"
OID_EKU_IPSEC_TUNNEL = "1.3.6.1.5.5.7.3.6"
OID_EKU_MICROSOFT_LIFETIME_SIGNING = "1.3.6.1.4.1.311.10.3.13"
OID_EKU_MICROSOFT_CSP_SIGNATURE = "1.3.6.1.4.1.311.10.3.16"
OID_EKU_MICROSOFT_SGC_SERIALIZED = "1.3.6.1.4.1.311.10.3.3.1"
OID_EKU_SBGP_CERT_AA_SERVICE_AUTH = "1.3.6.1.5.5.7.3.11"
OID_EKU_EAP_OVER_LAN = "1.3.6.1.5.5.7.3.14"
OID_EKU_APPLE_SYSTEM_IDENTITY = "1.2.840.113635.100.4.4"
OID_EKU_MICROSOFT_KEY_RECOVERY_3 = "1.3.6.1.4.1.311.10.3.11"
OID_EKU_MICROSOFT_CERT_TRUST_LIST_SIGNING = "1.3.6.1.4.1.311.10.3.1"
OID_EKU_MICROSOFT_DRM = "1.3.6.1.4.1.311.10.5.1"
OID_EKU_MICROSOFT_LICENSES = "1.3.6.1.4.1.311.10.5.3"
OID_EKU_MICROSOFT_LICENSE_SERVER = "1.3.6.1.4.1.311.10.5.4"
OID_EKU_MICROSOFT_ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"
OID_EKU_APPLE_SOFTWARE_UPDATE_SIGNING = "1.2.840.113635.100.4.1.2"
OID_EKU_APPLE_CRYPTO_TEST_ENV = "1.2.840.113635.100.4.5.3"
OID_EKU_MICROSOFT_EMBEDDED_NT_CRYPTO = "1.3.6.1.4.1.311.10.3.8"
OID_EKU_MICROSOFT_DRM_INDIVIDUALIZATION = "1.3.6.1.4.1.311.10.5.2"
OID_EKU_MICROSOFT_KEY_RECOVERY_21 = "1.3.6.1.4.1.311.21.6"
OID_EKU_EAP_OVER_PPP = "1.3.6.1.5.5.7.3.13"
OID_EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
OID_EKU_APPLE_CRYPTO_PRODUCTION_ENV = "1.2.840.113635.100.4.5.1"
OID_EKU_APPLE_CRYPTO_TIER1_QOS = "1.2.840.113635.100.4.6.2"
OID_EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
OID_EKU_APPLE_CRYPTO_DEVELOPMENT_ENV = "1.2.840.113635.100.4.5.4"
OID_EKU_APPLE_CRYPTO_TIER0_QOS = "1.2.840.113635.100.4.6.1"
OID_EKU_APPLE_CRYPTO_TIER2_QOS = "1.2.840.113635.100.4.6.3"
OID_EKU_MICROSOFT_MOBILE_DEVICE_SOFTWARE = "1.3.6.1.4.1.311.10.3.14"
OID_EKU_MICROSOFT_NT5_CRYPTO = "1.3.6.1.4.1.311.10.3.6"
OID_EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
OID_EKU_APPLE_CODE_SIGNING_THIRD_PARTY = "1.2.840.113635.100.4.1.3"
OID_EKU_MICROSOFT_TIMESTAMP_SIGNING = "1.3.6.1.4.1.311.10.3.2"
OID_EKU_APPLE_CODE_SIGNING_DEVELOPMENT = "1.2.840.113635.100.4.1.1"
OID_EKU_APPLE_CRYPTO_QOS = "1.2.840.113635.100.4.6"
OID_EKU_MICROSOFT_DOCUMENT_SIGNING = "1.3.6.1.4.1.311.10.3.12"
OID_EKU_MICROSOFT_ENCRYPTED_FILE_SYSTEM = "1.3.6.1.4.1.311.10.3.4"
OID_EKU_MICROSOFT_WHQL_CRYPTO = "1.3.6.1.4.1.311.10.3.5"
OID_EKU_MICROSOFT_ROOT_LIST_SIGNER = "1.3.6.1.4.1.311.10.3.9"
OID_EKU_MICROSOFT_SYSTEM_HEALTH = "1.3.6.1.4.1.311.47.1.1"
OID_EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
OID_EKU_NETSCAPE_SERVER_GATED_CRYPTO = "2.16.840.1.113730.4.1"
OID_EKU_APPLE_CRYPTO_TIER3_QOS = "1.2.840.113635.100.4.6.4"
OID_EKU_MICROSOFT_SMART_DISPLAY = "1.3.6.1.4.1.311.10.3.15"
OID_EKU_MICROSOFT_EFS_RECOVERY = "1.3.6.1.4.1.311.10.3.4.1"
OID_EKU_MICROSOFT_KERNEL_MODE_CODE_SIGNING = "1.3.6.1.4.1.311.61.1.1"
OID_EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
OID_EKU_IPSEC_END_SYSTEM = "1.3.6.1.5.5.7.3.5"
OID_EKU_IPSEC_USER = "1.3.6.1.5.5.7.3.7"
OID_EKU_MICROSOFT_QUALIFIED_SUBORDINATE = "1.3.6.1.4.1.311.10.3.10"
OID_EKU_APPLE_RESOURCE_SIGNING = "1.2.840.113635.100.4.1.4"
OID_EKU_MICROSOFT_OEM_WHQL_CRYPTO = "1.3.6.1.4.1.311.10.3.7"
OID_EKU_MICROSOFT_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
OID_EKU_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
OID_EKU_MICROSOFT_SERVER_GATED_CRYPTO = "1.3.6.1.4.1.311.10.3.3"
OID_EKU_MICROSOFT_CA_EXCHANGE = "1.3.6.1.4.1.311.21.5"
OID_EKU_DVCS = "1.3.6.1.5.5.7.3.10"
OID_EKU_APPLE_ICHAT_SIGNING = "1.2.840.113635.100.4.2"
OID_EKU_APPLE_ICHAT_ENCRYPTION = "1.2.840.113635.100.4.3"
)
var (
oidExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
oidExtKeyUsageAppleCodeSigningDevelopment = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 1}
oidExtKeyUsageAppleCryptoQos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6}
oidExtKeyUsageMicrosoftDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
oidExtKeyUsageMicrosoftEncryptedFileSystem = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4}
oidExtKeyUsageMicrosoftWhqlCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 5}
oidExtKeyUsageMicrosoftRootListSigner = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 9}
oidExtKeyUsageMicrosoftSystemHealth = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 47, 1, 1}
oidExtKeyUsageNetscapeServerGatedCrypto = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
oidExtKeyUsageAppleCryptoTier3Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 4}
oidExtKeyUsageMicrosoftSmartDisplay = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 15}
oidExtKeyUsageMicrosoftEfsRecovery = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4, 1}
oidExtKeyUsageMicrosoftKernelModeCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
oidExtKeyUsageServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
oidExtKeyUsageIpsecEndSystem = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
oidExtKeyUsageIpsecUser = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
oidExtKeyUsageMicrosoftQualifiedSubordinate = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 10}
oidExtKeyUsageAppleResourceSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 4}
oidExtKeyUsageMicrosoftOemWhqlCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 7}
oidExtKeyUsageMicrosoftSmartcardLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
oidExtKeyUsageEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
oidExtKeyUsageMicrosoftServerGatedCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
oidExtKeyUsageMicrosoftCaExchange = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 5}
oidExtKeyUsageDvcs = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 10}
oidExtKeyUsageAppleIchatSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 2}
oidExtKeyUsageAppleIchatEncryption = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 3}
oidExtKeyUsageAppleCodeSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1}
oidExtKeyUsageAppleCryptoEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5}
oidExtKeyUsageMicrosoftSystemHealthLoophole = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 47, 1, 3}
oidExtKeyUsageAny = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
oidExtKeyUsageAppleCryptoMaintenanceEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 2}
oidExtKeyUsageIpsecTunnel = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
oidExtKeyUsageMicrosoftLifetimeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 13}
oidExtKeyUsageMicrosoftCspSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 16}
oidExtKeyUsageMicrosoftSgcSerialized = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3, 1}
oidExtKeyUsageSbgpCertAaServiceAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 11}
oidExtKeyUsageEapOverLan = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 14}
oidExtKeyUsageAppleSystemIdentity = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 4}
oidExtKeyUsageMicrosoftKeyRecovery3 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 11}
oidExtKeyUsageMicrosoftCertTrustListSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 1}
oidExtKeyUsageMicrosoftDrm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 1}
oidExtKeyUsageMicrosoftLicenses = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 3}
oidExtKeyUsageMicrosoftLicenseServer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 4}
oidExtKeyUsageMicrosoftEnrollmentAgent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 1}
oidExtKeyUsageAppleSoftwareUpdateSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 2}
oidExtKeyUsageAppleCryptoTestEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 3}
oidExtKeyUsageMicrosoftEmbeddedNtCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 8}
oidExtKeyUsageMicrosoftDrmIndividualization = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 2}
oidExtKeyUsageMicrosoftKeyRecovery21 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 6}
oidExtKeyUsageEapOverPpp = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 13}
oidExtKeyUsageOcspSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
oidExtKeyUsageAppleCryptoProductionEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 1}
oidExtKeyUsageAppleCryptoTier1Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 2}
oidExtKeyUsageClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
oidExtKeyUsageAppleCryptoDevelopmentEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 4}
oidExtKeyUsageAppleCryptoTier0Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 1}
oidExtKeyUsageAppleCryptoTier2Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 3}
oidExtKeyUsageMicrosoftMobileDeviceSoftware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 14}
oidExtKeyUsageMicrosoftNt5Crypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 6}
oidExtKeyUsageCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
oidExtKeyUsageAppleCodeSigningThirdParty = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 3}
oidExtKeyUsageMicrosoftTimestampSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 2}
)
const (
ExtKeyUsageAppleResourceSigning ExtKeyUsage = iota
ExtKeyUsageMicrosoftOemWhqlCrypto
ExtKeyUsageMicrosoftSmartcardLogon
ExtKeyUsageEmailProtection
ExtKeyUsageMicrosoftServerGatedCrypto
ExtKeyUsageMicrosoftCaExchange
ExtKeyUsageDvcs
ExtKeyUsageAppleIchatSigning
ExtKeyUsageAppleIchatEncryption
ExtKeyUsageAppleCodeSigning
ExtKeyUsageAppleCryptoEnv
ExtKeyUsageMicrosoftSystemHealthLoophole
ExtKeyUsageAny
ExtKeyUsageAppleCryptoMaintenanceEnv
ExtKeyUsageIpsecTunnel
ExtKeyUsageMicrosoftLifetimeSigning
ExtKeyUsageMicrosoftCspSignature
ExtKeyUsageMicrosoftSgcSerialized
ExtKeyUsageSbgpCertAaServiceAuth
ExtKeyUsageEapOverLan
ExtKeyUsageMicrosoftEnrollmentAgent
ExtKeyUsageAppleSystemIdentity
ExtKeyUsageMicrosoftKeyRecovery3
ExtKeyUsageMicrosoftCertTrustListSigning
ExtKeyUsageMicrosoftDrm
ExtKeyUsageMicrosoftLicenses
ExtKeyUsageMicrosoftLicenseServer
ExtKeyUsageOcspSigning
ExtKeyUsageAppleSoftwareUpdateSigning
ExtKeyUsageAppleCryptoTestEnv
ExtKeyUsageMicrosoftEmbeddedNtCrypto
ExtKeyUsageMicrosoftDrmIndividualization
ExtKeyUsageMicrosoftKeyRecovery21
ExtKeyUsageEapOverPpp
ExtKeyUsageAppleCryptoProductionEnv
ExtKeyUsageAppleCryptoTier1Qos
ExtKeyUsageClientAuth
ExtKeyUsageAppleCryptoDevelopmentEnv
ExtKeyUsageAppleCryptoTier0Qos
ExtKeyUsageAppleCryptoTier2Qos
ExtKeyUsageMicrosoftMobileDeviceSoftware
ExtKeyUsageMicrosoftNt5Crypto
ExtKeyUsageCodeSigning
ExtKeyUsageAppleCodeSigningThirdParty
ExtKeyUsageMicrosoftTimestampSigning
ExtKeyUsageMicrosoftSystemHealth
ExtKeyUsageTimeStamping
ExtKeyUsageAppleCodeSigningDevelopment
ExtKeyUsageAppleCryptoQos
ExtKeyUsageMicrosoftDocumentSigning
ExtKeyUsageMicrosoftEncryptedFileSystem
ExtKeyUsageMicrosoftWhqlCrypto
ExtKeyUsageMicrosoftRootListSigner
ExtKeyUsageNetscapeServerGatedCrypto
ExtKeyUsageAppleCryptoTier3Qos
ExtKeyUsageMicrosoftSmartDisplay
ExtKeyUsageMicrosoftEfsRecovery
ExtKeyUsageMicrosoftKernelModeCodeSigning
ExtKeyUsageServerAuth
ExtKeyUsageIpsecEndSystem
ExtKeyUsageIpsecUser
ExtKeyUsageMicrosoftQualifiedSubordinate
)
type auxExtendedKeyUsage struct {
EapOverPpp bool `json:"eap_over_ppp,omitempty"`
OcspSigning bool `json:"ocsp_signing,omitempty"`
AppleSoftwareUpdateSigning bool `json:"apple_software_update_signing,omitempty"`
AppleCryptoTestEnv bool `json:"apple_crypto_test_env,omitempty"`
MicrosoftEmbeddedNtCrypto bool `json:"microsoft_embedded_nt_crypto,omitempty"`
MicrosoftDrmIndividualization bool `json:"microsoft_drm_individualization,omitempty"`
MicrosoftKeyRecovery21 bool `json:"microsoft_key_recovery_21,omitempty"`
AppleCryptoProductionEnv bool `json:"apple_crypto_production_env,omitempty"`
AppleCryptoTier1Qos bool `json:"apple_crypto_tier1_qos,omitempty"`
ClientAuth bool `json:"client_auth,omitempty"`
CodeSigning bool `json:"code_signing,omitempty"`
AppleCryptoDevelopmentEnv bool `json:"apple_crypto_development_env,omitempty"`
AppleCryptoTier0Qos bool `json:"apple_crypto_tier0_qos,omitempty"`
AppleCryptoTier2Qos bool `json:"apple_crypto_tier2_qos,omitempty"`
MicrosoftMobileDeviceSoftware bool `json:"microsoft_mobile_device_software,omitempty"`
MicrosoftNt5Crypto bool `json:"microsoft_nt5_crypto,omitempty"`
AppleCodeSigningThirdParty bool `json:"apple_code_signing_third_party,omitempty"`
MicrosoftTimestampSigning bool `json:"microsoft_timestamp_signing,omitempty"`
MicrosoftRootListSigner bool `json:"microsoft_root_list_signer,omitempty"`
MicrosoftSystemHealth bool `json:"microsoft_system_health,omitempty"`
TimeStamping bool `json:"time_stamping,omitempty"`
AppleCodeSigningDevelopment bool `json:"apple_code_signing_development,omitempty"`
AppleCryptoQos bool `json:"apple_crypto_qos,omitempty"`
MicrosoftDocumentSigning bool `json:"microsoft_document_signing,omitempty"`
MicrosoftEncryptedFileSystem bool `json:"microsoft_encrypted_file_system,omitempty"`
MicrosoftWhqlCrypto bool `json:"microsoft_whql_crypto,omitempty"`
NetscapeServerGatedCrypto bool `json:"netscape_server_gated_crypto,omitempty"`
AppleCryptoTier3Qos bool `json:"apple_crypto_tier3_qos,omitempty"`
MicrosoftSmartDisplay bool `json:"microsoft_smart_display,omitempty"`
MicrosoftEfsRecovery bool `json:"microsoft_efs_recovery,omitempty"`
MicrosoftKernelModeCodeSigning bool `json:"microsoft_kernel_mode_code_signing,omitempty"`
ServerAuth bool `json:"server_auth,omitempty"`
IpsecEndSystem bool `json:"ipsec_end_system,omitempty"`
IpsecUser bool `json:"ipsec_user,omitempty"`
MicrosoftQualifiedSubordinate bool `json:"microsoft_qualified_subordinate,omitempty"`
AppleResourceSigning bool `json:"apple_resource_signing,omitempty"`
MicrosoftOemWhqlCrypto bool `json:"microsoft_oem_whql_crypto,omitempty"`
MicrosoftSmartcardLogon bool `json:"microsoft_smartcard_logon,omitempty"`
EmailProtection bool `json:"email_protection,omitempty"`
MicrosoftServerGatedCrypto bool `json:"microsoft_server_gated_crypto,omitempty"`
MicrosoftCaExchange bool `json:"microsoft_ca_exchange,omitempty"`
Dvcs bool `json:"dvcs,omitempty"`
AppleIchatSigning bool `json:"apple_ichat_signing,omitempty"`
AppleIchatEncryption bool `json:"apple_ichat_encryption,omitempty"`
AppleCodeSigning bool `json:"apple_code_signing,omitempty"`
AppleCryptoEnv bool `json:"apple_crypto_env,omitempty"`
MicrosoftSystemHealthLoophole bool `json:"microsoft_system_health_loophole,omitempty"`
Any bool `json:"any,omitempty"`
AppleCryptoMaintenanceEnv bool `json:"apple_crypto_maintenance_env,omitempty"`
IpsecTunnel bool `json:"ipsec_tunnel,omitempty"`
MicrosoftLifetimeSigning bool `json:"microsoft_lifetime_signing,omitempty"`
MicrosoftCspSignature bool `json:"microsoft_csp_signature,omitempty"`
MicrosoftSgcSerialized bool `json:"microsoft_sgc_serialized,omitempty"`
SbgpCertAaServiceAuth bool `json:"sbgp_cert_aa_service_auth,omitempty"`
EapOverLan bool `json:"eap_over_lan,omitempty"`
MicrosoftLicenseServer bool `json:"microsoft_license_server,omitempty"`
MicrosoftEnrollmentAgent bool `json:"microsoft_enrollment_agent,omitempty"`
AppleSystemIdentity bool `json:"apple_system_identity,omitempty"`
MicrosoftKeyRecovery3 bool `json:"microsoft_key_recovery_3,omitempty"`
MicrosoftCertTrustListSigning bool `json:"microsoft_cert_trust_list_signing,omitempty"`
MicrosoftDrm bool `json:"microsoft_drm,omitempty"`
MicrosoftLicenses bool `json:"microsoft_licenses,omitempty"`
Unknown []string `json:"unknown,omitempty"`}

func (aux *auxExtendedKeyUsage) populateFromASN1(oid asn1.ObjectIdentifier) {
s := oid.String()
switch s {
case OID_EKU_MICROSOFT_EMBEDDED_NT_CRYPTO:
aux.MicrosoftEmbeddedNtCrypto = true
case OID_EKU_MICROSOFT_DRM_INDIVIDUALIZATION:
aux.MicrosoftDrmIndividualization = true
case OID_EKU_MICROSOFT_KEY_RECOVERY_21:
aux.MicrosoftKeyRecovery21 = true
case OID_EKU_EAP_OVER_PPP:
aux.EapOverPpp = true
case OID_EKU_OCSP_SIGNING:
aux.OcspSigning = true
case OID_EKU_APPLE_SOFTWARE_UPDATE_SIGNING:
aux.AppleSoftwareUpdateSigning = true
case OID_EKU_APPLE_CRYPTO_TEST_ENV:
aux.AppleCryptoTestEnv = true
case OID_EKU_CLIENT_AUTH:
aux.ClientAuth = true
case OID_EKU_APPLE_CRYPTO_PRODUCTION_ENV:
aux.AppleCryptoProductionEnv = true
case OID_EKU_APPLE_CRYPTO_TIER1_QOS:
aux.AppleCryptoTier1Qos = true
case OID_EKU_APPLE_CRYPTO_TIER2_QOS:
aux.AppleCryptoTier2Qos = true
case OID_EKU_MICROSOFT_MOBILE_DEVICE_SOFTWARE:
aux.MicrosoftMobileDeviceSoftware = true
case OID_EKU_MICROSOFT_NT5_CRYPTO:
aux.MicrosoftNt5Crypto = true
case OID_EKU_CODE_SIGNING:
aux.CodeSigning = true
case OID_EKU_APPLE_CRYPTO_DEVELOPMENT_ENV:
aux.AppleCryptoDevelopmentEnv = true
case OID_EKU_APPLE_CRYPTO_TIER0_QOS:
aux.AppleCryptoTier0Qos = true
case OID_EKU_APPLE_CODE_SIGNING_THIRD_PARTY:
aux.AppleCodeSigningThirdParty = true
case OID_EKU_MICROSOFT_TIMESTAMP_SIGNING:
aux.MicrosoftTimestampSigning = true
case OID_EKU_MICROSOFT_DOCUMENT_SIGNING:
aux.MicrosoftDocumentSigning = true
case OID_EKU_MICROSOFT_ENCRYPTED_FILE_SYSTEM:
aux.MicrosoftEncryptedFileSystem = true
case OID_EKU_MICROSOFT_WHQL_CRYPTO:
aux.MicrosoftWhqlCrypto = true
case OID_EKU_MICROSOFT_ROOT_LIST_SIGNER:
aux.MicrosoftRootListSigner = true
case OID_EKU_MICROSOFT_SYSTEM_HEALTH:
aux.MicrosoftSystemHealth = true
case OID_EKU_TIME_STAMPING:
aux.TimeStamping = true
case OID_EKU_APPLE_CODE_SIGNING_DEVELOPMENT:
aux.AppleCodeSigningDevelopment = true
case OID_EKU_APPLE_CRYPTO_QOS:
aux.AppleCryptoQos = true
case OID_EKU_NETSCAPE_SERVER_GATED_CRYPTO:
aux.NetscapeServerGatedCrypto = true
case OID_EKU_APPLE_CRYPTO_TIER3_QOS:
aux.AppleCryptoTier3Qos = true
case OID_EKU_MICROSOFT_SMART_DISPLAY:
aux.MicrosoftSmartDisplay = true
case OID_EKU_SERVER_AUTH:
aux.ServerAuth = true
case OID_EKU_IPSEC_END_SYSTEM:
aux.IpsecEndSystem = true
case OID_EKU_IPSEC_USER:
aux.IpsecUser = true
case OID_EKU_MICROSOFT_EFS_RECOVERY:
aux.MicrosoftEfsRecovery = true
case OID_EKU_MICROSOFT_KERNEL_MODE_CODE_SIGNING:
aux.MicrosoftKernelModeCodeSigning = true
case OID_EKU_MICROSOFT_QUALIFIED_SUBORDINATE:
aux.MicrosoftQualifiedSubordinate = true
case OID_EKU_MICROSOFT_SMARTCARD_LOGON:
aux.MicrosoftSmartcardLogon = true
case OID_EKU_EMAIL_PROTECTION:
aux.EmailProtection = true
case OID_EKU_APPLE_RESOURCE_SIGNING:
aux.AppleResourceSigning = true
case OID_EKU_MICROSOFT_OEM_WHQL_CRYPTO:
aux.MicrosoftOemWhqlCrypto = true
case OID_EKU_DVCS:
aux.Dvcs = true
case OID_EKU_MICROSOFT_SERVER_GATED_CRYPTO:
aux.MicrosoftServerGatedCrypto = true
case OID_EKU_MICROSOFT_CA_EXCHANGE:
aux.MicrosoftCaExchange = true
case OID_EKU_APPLE_ICHAT_SIGNING:
aux.AppleIchatSigning = true
case OID_EKU_APPLE_ICHAT_ENCRYPTION:
aux.AppleIchatEncryption = true
case OID_EKU_MICROSOFT_SYSTEM_HEALTH_LOOPHOLE:
aux.MicrosoftSystemHealthLoophole = true
case OID_EKU_ANY:
aux.Any = true
case OID_EKU_APPLE_CODE_SIGNING:
aux.AppleCodeSigning = true
case OID_EKU_APPLE_CRYPTO_ENV:
aux.AppleCryptoEnv = true
case OID_EKU_APPLE_CRYPTO_MAINTENANCE_ENV:
aux.AppleCryptoMaintenanceEnv = true
case OID_EKU_IPSEC_TUNNEL:
aux.IpsecTunnel = true
case OID_EKU_MICROSOFT_SGC_SERIALIZED:
aux.MicrosoftSgcSerialized = true
case OID_EKU_SBGP_CERT_AA_SERVICE_AUTH:
aux.SbgpCertAaServiceAuth = true
case OID_EKU_EAP_OVER_LAN:
aux.EapOverLan = true
case OID_EKU_MICROSOFT_LIFETIME_SIGNING:
aux.MicrosoftLifetimeSigning = true
case OID_EKU_MICROSOFT_CSP_SIGNATURE:
aux.MicrosoftCspSignature = true
case OID_EKU_MICROSOFT_CERT_TRUST_LIST_SIGNING:
aux.MicrosoftCertTrustListSigning = true
case OID_EKU_MICROSOFT_DRM:
aux.MicrosoftDrm = true
case OID_EKU_MICROSOFT_LICENSES:
aux.MicrosoftLicenses = true
case OID_EKU_MICROSOFT_LICENSE_SERVER:
aux.MicrosoftLicenseServer = true
case OID_EKU_MICROSOFT_ENROLLMENT_AGENT:
aux.MicrosoftEnrollmentAgent = true
case OID_EKU_APPLE_SYSTEM_IDENTITY:
aux.AppleSystemIdentity = true
case OID_EKU_MICROSOFT_KEY_RECOVERY_3:
aux.MicrosoftKeyRecovery3 = true
default:
}
return}

func (aux *auxExtendedKeyUsage) populateFromExtKeyUsage(eku ExtKeyUsage) {
switch eku {
case ExtKeyUsageAppleCryptoProductionEnv:
aux.AppleCryptoProductionEnv = true
case ExtKeyUsageAppleCryptoTier1Qos:
aux.AppleCryptoTier1Qos = true
case ExtKeyUsageClientAuth:
aux.ClientAuth = true
case ExtKeyUsageMicrosoftMobileDeviceSoftware:
aux.MicrosoftMobileDeviceSoftware = true
case ExtKeyUsageMicrosoftNt5Crypto:
aux.MicrosoftNt5Crypto = true
case ExtKeyUsageCodeSigning:
aux.CodeSigning = true
case ExtKeyUsageAppleCryptoDevelopmentEnv:
aux.AppleCryptoDevelopmentEnv = true
case ExtKeyUsageAppleCryptoTier0Qos:
aux.AppleCryptoTier0Qos = true
case ExtKeyUsageAppleCryptoTier2Qos:
aux.AppleCryptoTier2Qos = true
case ExtKeyUsageAppleCodeSigningThirdParty:
aux.AppleCodeSigningThirdParty = true
case ExtKeyUsageMicrosoftTimestampSigning:
aux.MicrosoftTimestampSigning = true
case ExtKeyUsageMicrosoftEncryptedFileSystem:
aux.MicrosoftEncryptedFileSystem = true
case ExtKeyUsageMicrosoftWhqlCrypto:
aux.MicrosoftWhqlCrypto = true
case ExtKeyUsageMicrosoftRootListSigner:
aux.MicrosoftRootListSigner = true
case ExtKeyUsageMicrosoftSystemHealth:
aux.MicrosoftSystemHealth = true
case ExtKeyUsageTimeStamping:
aux.TimeStamping = true
case ExtKeyUsageAppleCodeSigningDevelopment:
aux.AppleCodeSigningDevelopment = true
case ExtKeyUsageAppleCryptoQos:
aux.AppleCryptoQos = true
case ExtKeyUsageMicrosoftDocumentSigning:
aux.MicrosoftDocumentSigning = true
case ExtKeyUsageNetscapeServerGatedCrypto:
aux.NetscapeServerGatedCrypto = true
case ExtKeyUsageAppleCryptoTier3Qos:
aux.AppleCryptoTier3Qos = true
case ExtKeyUsageMicrosoftSmartDisplay:
aux.MicrosoftSmartDisplay = true
case ExtKeyUsageIpsecEndSystem:
aux.IpsecEndSystem = true
case ExtKeyUsageIpsecUser:
aux.IpsecUser = true
case ExtKeyUsageMicrosoftEfsRecovery:
aux.MicrosoftEfsRecovery = true
case ExtKeyUsageMicrosoftKernelModeCodeSigning:
aux.MicrosoftKernelModeCodeSigning = true
case ExtKeyUsageServerAuth:
aux.ServerAuth = true
case ExtKeyUsageMicrosoftQualifiedSubordinate:
aux.MicrosoftQualifiedSubordinate = true
case ExtKeyUsageEmailProtection:
aux.EmailProtection = true
case ExtKeyUsageAppleResourceSigning:
aux.AppleResourceSigning = true
case ExtKeyUsageMicrosoftOemWhqlCrypto:
aux.MicrosoftOemWhqlCrypto = true
case ExtKeyUsageMicrosoftSmartcardLogon:
aux.MicrosoftSmartcardLogon = true
case ExtKeyUsageMicrosoftServerGatedCrypto:
aux.MicrosoftServerGatedCrypto = true
case ExtKeyUsageMicrosoftCaExchange:
aux.MicrosoftCaExchange = true
case ExtKeyUsageDvcs:
aux.Dvcs = true
case ExtKeyUsageAppleIchatSigning:
aux.AppleIchatSigning = true
case ExtKeyUsageAppleIchatEncryption:
aux.AppleIchatEncryption = true
case ExtKeyUsageAny:
aux.Any = true
case ExtKeyUsageAppleCodeSigning:
aux.AppleCodeSigning = true
case ExtKeyUsageAppleCryptoEnv:
aux.AppleCryptoEnv = true
case ExtKeyUsageMicrosoftSystemHealthLoophole:
aux.MicrosoftSystemHealthLoophole = true
case ExtKeyUsageAppleCryptoMaintenanceEnv:
aux.AppleCryptoMaintenanceEnv = true
case ExtKeyUsageIpsecTunnel:
aux.IpsecTunnel = true
case ExtKeyUsageSbgpCertAaServiceAuth:
aux.SbgpCertAaServiceAuth = true
case ExtKeyUsageEapOverLan:
aux.EapOverLan = true
case ExtKeyUsageMicrosoftLifetimeSigning:
aux.MicrosoftLifetimeSigning = true
case ExtKeyUsageMicrosoftCspSignature:
aux.MicrosoftCspSignature = true
case ExtKeyUsageMicrosoftSgcSerialized:
aux.MicrosoftSgcSerialized = true
case ExtKeyUsageMicrosoftDrm:
aux.MicrosoftDrm = true
case ExtKeyUsageMicrosoftLicenses:
aux.MicrosoftLicenses = true
case ExtKeyUsageMicrosoftLicenseServer:
aux.MicrosoftLicenseServer = true
case ExtKeyUsageMicrosoftEnrollmentAgent:
aux.MicrosoftEnrollmentAgent = true
case ExtKeyUsageAppleSystemIdentity:
aux.AppleSystemIdentity = true
case ExtKeyUsageMicrosoftKeyRecovery3:
aux.MicrosoftKeyRecovery3 = true
case ExtKeyUsageMicrosoftCertTrustListSigning:
aux.MicrosoftCertTrustListSigning = true
case ExtKeyUsageMicrosoftDrmIndividualization:
aux.MicrosoftDrmIndividualization = true
case ExtKeyUsageMicrosoftKeyRecovery21:
aux.MicrosoftKeyRecovery21 = true
case ExtKeyUsageEapOverPpp:
aux.EapOverPpp = true
case ExtKeyUsageOcspSigning:
aux.OcspSigning = true
case ExtKeyUsageAppleSoftwareUpdateSigning:
aux.AppleSoftwareUpdateSigning = true
case ExtKeyUsageAppleCryptoTestEnv:
aux.AppleCryptoTestEnv = true
case ExtKeyUsageMicrosoftEmbeddedNtCrypto:
aux.MicrosoftEmbeddedNtCrypto = true
default:
}
return}


var ekuOIDs map[string]asn1.ObjectIdentifier


var ekuConstants map[string]ExtKeyUsage

func init() {
ekuOIDs = make(map[string]asn1.ObjectIdentifier)
ekuOIDs[OID_EKU_APPLE_CRYPTO_DEVELOPMENT_ENV] = oidExtKeyUsageAppleCryptoDevelopmentEnv
ekuOIDs[OID_EKU_APPLE_CRYPTO_TIER0_QOS] = oidExtKeyUsageAppleCryptoTier0Qos
ekuOIDs[OID_EKU_APPLE_CRYPTO_TIER2_QOS] = oidExtKeyUsageAppleCryptoTier2Qos
ekuOIDs[OID_EKU_MICROSOFT_MOBILE_DEVICE_SOFTWARE] = oidExtKeyUsageMicrosoftMobileDeviceSoftware
ekuOIDs[OID_EKU_MICROSOFT_NT5_CRYPTO] = oidExtKeyUsageMicrosoftNt5Crypto
ekuOIDs[OID_EKU_CODE_SIGNING] = oidExtKeyUsageCodeSigning
ekuOIDs[OID_EKU_APPLE_CODE_SIGNING_THIRD_PARTY] = oidExtKeyUsageAppleCodeSigningThirdParty
ekuOIDs[OID_EKU_MICROSOFT_TIMESTAMP_SIGNING] = oidExtKeyUsageMicrosoftTimestampSigning
ekuOIDs[OID_EKU_MICROSOFT_SYSTEM_HEALTH] = oidExtKeyUsageMicrosoftSystemHealth
ekuOIDs[OID_EKU_TIME_STAMPING] = oidExtKeyUsageTimeStamping
ekuOIDs[OID_EKU_APPLE_CODE_SIGNING_DEVELOPMENT] = oidExtKeyUsageAppleCodeSigningDevelopment
ekuOIDs[OID_EKU_APPLE_CRYPTO_QOS] = oidExtKeyUsageAppleCryptoQos
ekuOIDs[OID_EKU_MICROSOFT_DOCUMENT_SIGNING] = oidExtKeyUsageMicrosoftDocumentSigning
ekuOIDs[OID_EKU_MICROSOFT_ENCRYPTED_FILE_SYSTEM] = oidExtKeyUsageMicrosoftEncryptedFileSystem
ekuOIDs[OID_EKU_MICROSOFT_WHQL_CRYPTO] = oidExtKeyUsageMicrosoftWhqlCrypto
ekuOIDs[OID_EKU_MICROSOFT_ROOT_LIST_SIGNER] = oidExtKeyUsageMicrosoftRootListSigner
ekuOIDs[OID_EKU_NETSCAPE_SERVER_GATED_CRYPTO] = oidExtKeyUsageNetscapeServerGatedCrypto
ekuOIDs[OID_EKU_APPLE_CRYPTO_TIER3_QOS] = oidExtKeyUsageAppleCryptoTier3Qos
ekuOIDs[OID_EKU_MICROSOFT_SMART_DISPLAY] = oidExtKeyUsageMicrosoftSmartDisplay
ekuOIDs[OID_EKU_MICROSOFT_EFS_RECOVERY] = oidExtKeyUsageMicrosoftEfsRecovery
ekuOIDs[OID_EKU_MICROSOFT_KERNEL_MODE_CODE_SIGNING] = oidExtKeyUsageMicrosoftKernelModeCodeSigning
ekuOIDs[OID_EKU_SERVER_AUTH] = oidExtKeyUsageServerAuth
ekuOIDs[OID_EKU_IPSEC_END_SYSTEM] = oidExtKeyUsageIpsecEndSystem
ekuOIDs[OID_EKU_IPSEC_USER] = oidExtKeyUsageIpsecUser
ekuOIDs[OID_EKU_MICROSOFT_QUALIFIED_SUBORDINATE] = oidExtKeyUsageMicrosoftQualifiedSubordinate
ekuOIDs[OID_EKU_APPLE_RESOURCE_SIGNING] = oidExtKeyUsageAppleResourceSigning
ekuOIDs[OID_EKU_MICROSOFT_OEM_WHQL_CRYPTO] = oidExtKeyUsageMicrosoftOemWhqlCrypto
ekuOIDs[OID_EKU_MICROSOFT_SMARTCARD_LOGON] = oidExtKeyUsageMicrosoftSmartcardLogon
ekuOIDs[OID_EKU_EMAIL_PROTECTION] = oidExtKeyUsageEmailProtection
ekuOIDs[OID_EKU_MICROSOFT_SERVER_GATED_CRYPTO] = oidExtKeyUsageMicrosoftServerGatedCrypto
ekuOIDs[OID_EKU_MICROSOFT_CA_EXCHANGE] = oidExtKeyUsageMicrosoftCaExchange
ekuOIDs[OID_EKU_DVCS] = oidExtKeyUsageDvcs
ekuOIDs[OID_EKU_APPLE_ICHAT_SIGNING] = oidExtKeyUsageAppleIchatSigning
ekuOIDs[OID_EKU_APPLE_ICHAT_ENCRYPTION] = oidExtKeyUsageAppleIchatEncryption
ekuOIDs[OID_EKU_APPLE_CODE_SIGNING] = oidExtKeyUsageAppleCodeSigning
ekuOIDs[OID_EKU_APPLE_CRYPTO_ENV] = oidExtKeyUsageAppleCryptoEnv
ekuOIDs[OID_EKU_MICROSOFT_SYSTEM_HEALTH_LOOPHOLE] = oidExtKeyUsageMicrosoftSystemHealthLoophole
ekuOIDs[OID_EKU_ANY] = oidExtKeyUsageAny
ekuOIDs[OID_EKU_APPLE_CRYPTO_MAINTENANCE_ENV] = oidExtKeyUsageAppleCryptoMaintenanceEnv
ekuOIDs[OID_EKU_IPSEC_TUNNEL] = oidExtKeyUsageIpsecTunnel
ekuOIDs[OID_EKU_MICROSOFT_LIFETIME_SIGNING] = oidExtKeyUsageMicrosoftLifetimeSigning
ekuOIDs[OID_EKU_MICROSOFT_CSP_SIGNATURE] = oidExtKeyUsageMicrosoftCspSignature
ekuOIDs[OID_EKU_MICROSOFT_SGC_SERIALIZED] = oidExtKeyUsageMicrosoftSgcSerialized
ekuOIDs[OID_EKU_SBGP_CERT_AA_SERVICE_AUTH] = oidExtKeyUsageSbgpCertAaServiceAuth
ekuOIDs[OID_EKU_EAP_OVER_LAN] = oidExtKeyUsageEapOverLan
ekuOIDs[OID_EKU_MICROSOFT_ENROLLMENT_AGENT] = oidExtKeyUsageMicrosoftEnrollmentAgent
ekuOIDs[OID_EKU_APPLE_SYSTEM_IDENTITY] = oidExtKeyUsageAppleSystemIdentity
ekuOIDs[OID_EKU_MICROSOFT_KEY_RECOVERY_3] = oidExtKeyUsageMicrosoftKeyRecovery3
ekuOIDs[OID_EKU_MICROSOFT_CERT_TRUST_LIST_SIGNING] = oidExtKeyUsageMicrosoftCertTrustListSigning
ekuOIDs[OID_EKU_MICROSOFT_DRM] = oidExtKeyUsageMicrosoftDrm
ekuOIDs[OID_EKU_MICROSOFT_LICENSES] = oidExtKeyUsageMicrosoftLicenses
ekuOIDs[OID_EKU_MICROSOFT_LICENSE_SERVER] = oidExtKeyUsageMicrosoftLicenseServer
ekuOIDs[OID_EKU_OCSP_SIGNING] = oidExtKeyUsageOcspSigning
ekuOIDs[OID_EKU_APPLE_SOFTWARE_UPDATE_SIGNING] = oidExtKeyUsageAppleSoftwareUpdateSigning
ekuOIDs[OID_EKU_APPLE_CRYPTO_TEST_ENV] = oidExtKeyUsageAppleCryptoTestEnv
ekuOIDs[OID_EKU_MICROSOFT_EMBEDDED_NT_CRYPTO] = oidExtKeyUsageMicrosoftEmbeddedNtCrypto
ekuOIDs[OID_EKU_MICROSOFT_DRM_INDIVIDUALIZATION] = oidExtKeyUsageMicrosoftDrmIndividualization
ekuOIDs[OID_EKU_MICROSOFT_KEY_RECOVERY_21] = oidExtKeyUsageMicrosoftKeyRecovery21
ekuOIDs[OID_EKU_EAP_OVER_PPP] = oidExtKeyUsageEapOverPpp
ekuOIDs[OID_EKU_APPLE_CRYPTO_PRODUCTION_ENV] = oidExtKeyUsageAppleCryptoProductionEnv
ekuOIDs[OID_EKU_APPLE_CRYPTO_TIER1_QOS] = oidExtKeyUsageAppleCryptoTier1Qos
ekuOIDs[OID_EKU_CLIENT_AUTH] = oidExtKeyUsageClientAuth

ekuConstants = make(map[string]ExtKeyUsage)
ekuConstants[OID_EKU_APPLE_ICHAT_SIGNING] = ExtKeyUsageAppleIchatSigning
ekuConstants[OID_EKU_APPLE_ICHAT_ENCRYPTION] = ExtKeyUsageAppleIchatEncryption
ekuConstants[OID_EKU_MICROSOFT_SYSTEM_HEALTH_LOOPHOLE] = ExtKeyUsageMicrosoftSystemHealthLoophole
ekuConstants[OID_EKU_ANY] = ExtKeyUsageAny
ekuConstants[OID_EKU_APPLE_CODE_SIGNING] = ExtKeyUsageAppleCodeSigning
ekuConstants[OID_EKU_APPLE_CRYPTO_ENV] = ExtKeyUsageAppleCryptoEnv
ekuConstants[OID_EKU_APPLE_CRYPTO_MAINTENANCE_ENV] = ExtKeyUsageAppleCryptoMaintenanceEnv
ekuConstants[OID_EKU_IPSEC_TUNNEL] = ExtKeyUsageIpsecTunnel
ekuConstants[OID_EKU_MICROSOFT_SGC_SERIALIZED] = ExtKeyUsageMicrosoftSgcSerialized
ekuConstants[OID_EKU_SBGP_CERT_AA_SERVICE_AUTH] = ExtKeyUsageSbgpCertAaServiceAuth
ekuConstants[OID_EKU_EAP_OVER_LAN] = ExtKeyUsageEapOverLan
ekuConstants[OID_EKU_MICROSOFT_LIFETIME_SIGNING] = ExtKeyUsageMicrosoftLifetimeSigning
ekuConstants[OID_EKU_MICROSOFT_CSP_SIGNATURE] = ExtKeyUsageMicrosoftCspSignature
ekuConstants[OID_EKU_MICROSOFT_CERT_TRUST_LIST_SIGNING] = ExtKeyUsageMicrosoftCertTrustListSigning
ekuConstants[OID_EKU_MICROSOFT_DRM] = ExtKeyUsageMicrosoftDrm
ekuConstants[OID_EKU_MICROSOFT_LICENSES] = ExtKeyUsageMicrosoftLicenses
ekuConstants[OID_EKU_MICROSOFT_LICENSE_SERVER] = ExtKeyUsageMicrosoftLicenseServer
ekuConstants[OID_EKU_MICROSOFT_ENROLLMENT_AGENT] = ExtKeyUsageMicrosoftEnrollmentAgent
ekuConstants[OID_EKU_APPLE_SYSTEM_IDENTITY] = ExtKeyUsageAppleSystemIdentity
ekuConstants[OID_EKU_MICROSOFT_KEY_RECOVERY_3] = ExtKeyUsageMicrosoftKeyRecovery3
ekuConstants[OID_EKU_MICROSOFT_EMBEDDED_NT_CRYPTO] = ExtKeyUsageMicrosoftEmbeddedNtCrypto
ekuConstants[OID_EKU_MICROSOFT_DRM_INDIVIDUALIZATION] = ExtKeyUsageMicrosoftDrmIndividualization
ekuConstants[OID_EKU_MICROSOFT_KEY_RECOVERY_21] = ExtKeyUsageMicrosoftKeyRecovery21
ekuConstants[OID_EKU_EAP_OVER_PPP] = ExtKeyUsageEapOverPpp
ekuConstants[OID_EKU_OCSP_SIGNING] = ExtKeyUsageOcspSigning
ekuConstants[OID_EKU_APPLE_SOFTWARE_UPDATE_SIGNING] = ExtKeyUsageAppleSoftwareUpdateSigning
ekuConstants[OID_EKU_APPLE_CRYPTO_TEST_ENV] = ExtKeyUsageAppleCryptoTestEnv
ekuConstants[OID_EKU_CLIENT_AUTH] = ExtKeyUsageClientAuth
ekuConstants[OID_EKU_APPLE_CRYPTO_PRODUCTION_ENV] = ExtKeyUsageAppleCryptoProductionEnv
ekuConstants[OID_EKU_APPLE_CRYPTO_TIER1_QOS] = ExtKeyUsageAppleCryptoTier1Qos
ekuConstants[OID_EKU_APPLE_CRYPTO_TIER2_QOS] = ExtKeyUsageAppleCryptoTier2Qos
ekuConstants[OID_EKU_MICROSOFT_MOBILE_DEVICE_SOFTWARE] = ExtKeyUsageMicrosoftMobileDeviceSoftware
ekuConstants[OID_EKU_MICROSOFT_NT5_CRYPTO] = ExtKeyUsageMicrosoftNt5Crypto
ekuConstants[OID_EKU_CODE_SIGNING] = ExtKeyUsageCodeSigning
ekuConstants[OID_EKU_APPLE_CRYPTO_DEVELOPMENT_ENV] = ExtKeyUsageAppleCryptoDevelopmentEnv
ekuConstants[OID_EKU_APPLE_CRYPTO_TIER0_QOS] = ExtKeyUsageAppleCryptoTier0Qos
ekuConstants[OID_EKU_APPLE_CODE_SIGNING_THIRD_PARTY] = ExtKeyUsageAppleCodeSigningThirdParty
ekuConstants[OID_EKU_MICROSOFT_TIMESTAMP_SIGNING] = ExtKeyUsageMicrosoftTimestampSigning
ekuConstants[OID_EKU_MICROSOFT_DOCUMENT_SIGNING] = ExtKeyUsageMicrosoftDocumentSigning
ekuConstants[OID_EKU_MICROSOFT_ENCRYPTED_FILE_SYSTEM] = ExtKeyUsageMicrosoftEncryptedFileSystem
ekuConstants[OID_EKU_MICROSOFT_WHQL_CRYPTO] = ExtKeyUsageMicrosoftWhqlCrypto
ekuConstants[OID_EKU_MICROSOFT_ROOT_LIST_SIGNER] = ExtKeyUsageMicrosoftRootListSigner
ekuConstants[OID_EKU_MICROSOFT_SYSTEM_HEALTH] = ExtKeyUsageMicrosoftSystemHealth
ekuConstants[OID_EKU_TIME_STAMPING] = ExtKeyUsageTimeStamping
ekuConstants[OID_EKU_APPLE_CODE_SIGNING_DEVELOPMENT] = ExtKeyUsageAppleCodeSigningDevelopment
ekuConstants[OID_EKU_APPLE_CRYPTO_QOS] = ExtKeyUsageAppleCryptoQos
ekuConstants[OID_EKU_NETSCAPE_SERVER_GATED_CRYPTO] = ExtKeyUsageNetscapeServerGatedCrypto
ekuConstants[OID_EKU_APPLE_CRYPTO_TIER3_QOS] = ExtKeyUsageAppleCryptoTier3Qos
ekuConstants[OID_EKU_MICROSOFT_SMART_DISPLAY] = ExtKeyUsageMicrosoftSmartDisplay
ekuConstants[OID_EKU_SERVER_AUTH] = ExtKeyUsageServerAuth
ekuConstants[OID_EKU_IPSEC_END_SYSTEM] = ExtKeyUsageIpsecEndSystem
ekuConstants[OID_EKU_IPSEC_USER] = ExtKeyUsageIpsecUser
ekuConstants[OID_EKU_MICROSOFT_EFS_RECOVERY] = ExtKeyUsageMicrosoftEfsRecovery
ekuConstants[OID_EKU_MICROSOFT_KERNEL_MODE_CODE_SIGNING] = ExtKeyUsageMicrosoftKernelModeCodeSigning
ekuConstants[OID_EKU_MICROSOFT_QUALIFIED_SUBORDINATE] = ExtKeyUsageMicrosoftQualifiedSubordinate
ekuConstants[OID_EKU_MICROSOFT_SMARTCARD_LOGON] = ExtKeyUsageMicrosoftSmartcardLogon
ekuConstants[OID_EKU_EMAIL_PROTECTION] = ExtKeyUsageEmailProtection
ekuConstants[OID_EKU_APPLE_RESOURCE_SIGNING] = ExtKeyUsageAppleResourceSigning
ekuConstants[OID_EKU_MICROSOFT_OEM_WHQL_CRYPTO] = ExtKeyUsageMicrosoftOemWhqlCrypto
ekuConstants[OID_EKU_DVCS] = ExtKeyUsageDvcs
ekuConstants[OID_EKU_MICROSOFT_SERVER_GATED_CRYPTO] = ExtKeyUsageMicrosoftServerGatedCrypto
ekuConstants[OID_EKU_MICROSOFT_CA_EXCHANGE] = ExtKeyUsageMicrosoftCaExchange
}
