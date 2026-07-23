package chrome

import utls "github.com/enetx/utls"

// ML-DSA (post-quantum) TLS 1.3 signature schemes that Chrome 150 advertises at the
// head of its signature_algorithms list. utls does not yet name them, so they are
// spelled as raw SignatureScheme code points (per the TLS ML-DSA draft). Without
// them a Chrome-150 UA ships a pre-150 JA4, which some Akamai deployments reject.
const (
	MLDSA44 utls.SignatureScheme = 0x0904
	MLDSA65 utls.SignatureScheme = 0x0905
	MLDSA87 utls.SignatureScheme = 0x0906
)

// HelloChrome_150 mirrors HelloChrome_144 but prepends the ML-DSA signature schemes to
// match Chrome 150's signature_algorithms (and therefore its JA4).
var HelloChrome_150 = utls.ClientHelloSpec{
	CipherSuites: []uint16{
		utls.GREASE_PLACEHOLDER,
		utls.TLS_AES_128_GCM_SHA256,
		utls.TLS_AES_256_GCM_SHA384,
		utls.TLS_CHACHA20_POLY1305_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	CompressionMethods: []byte{0x00},
	Extensions: utls.ShuffleChromeTLSExtensions(
		[]utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{
				Renegotiation: utls.RenegotiateOnceAsClient,
			},
			&utls.SupportedCurvesExtension{
				Curves: []utls.CurveID{
					utls.GREASE_PLACEHOLDER,
					utls.X25519MLKEM768,
					utls.X25519,
					utls.CurveP256,
					utls.CurveP384,
				},
			},
			&utls.SupportedPointsExtension{
				SupportedPoints: []byte{0x00},
			},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{
				AlpnProtocols: []string{"h2", "http/1.1"},
			},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					MLDSA44,
					MLDSA65,
					MLDSA87,
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
				},
			},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{
				KeyShares: []utls.KeyShare{
					{Group: utls.GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: utls.X25519MLKEM768},
					{Group: utls.X25519},
				},
			},
			&utls.PSKKeyExchangeModesExtension{
				Modes: []uint8{
					utls.PskModeDHE,
				},
			},
			&utls.SupportedVersionsExtension{
				Versions: []uint16{
					utls.GREASE_PLACEHOLDER,
					utls.VersionTLS13,
					utls.VersionTLS12,
				},
			},
			&utls.UtlsCompressCertExtension{
				Algorithms: []utls.CertCompressionAlgo{
					utls.CertCompressionBrotli,
				},
			},
			&utls.ApplicationSettingsExtensionNew{
				SupportedProtocols: []string{"h2"},
			},
			utls.BoringGREASEECH(),
			&utls.UtlsGREASEExtension{},
			&utls.UtlsPreSharedKeyExtension{},
		},
	),
}
