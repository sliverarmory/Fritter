package fritter

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxConfigStringBytes = 255
	maxAppDomainBytes    = 8
	maxDecoyPathBytes    = 519
	maxModuleNameBytes   = 8
	maxStagingBaseBytes  = 247
	maxHTTPAuthBytes     = 63

	guestOutputName = "fritter-loader"

	moduleDotNetDLL        = 1
	moduleDotNetExecutable = 2
	moduleNativeDLL        = 3
	moduleNativeExecutable = 4
	moduleVBScript         = 5
	moduleJScript          = 6
)

type normalizedGeneration struct {
	payload []byte

	inputName string
	class     string
	method    string
	runtime   string
	domain    string
	decoy     string
	server    string
	module    string

	format       uint32
	exit         uint32
	forkRVA      uint32
	entropy      uint32
	headers      uint32
	thread       uint32
	expectedType uint32

	moduleURL *url.URL
}

func normalizeGeneration(request Request) (normalizedGeneration, error) {
	var normalized normalizedGeneration
	payload := request.Payload
	if payload == nil {
		return normalized, invalid("payload", "is required")
	}
	switch value := payload.(type) {
	case *NativeExecutable:
		if value == nil {
			return normalized, invalid("payload", "is nil")
		}
		payload = *value
	case *NativeDLL:
		if value == nil {
			return normalized, invalid("payload", "is nil")
		}
		payload = *value
	case *DotNetExecutable:
		if value == nil {
			return normalized, invalid("payload", "is nil")
		}
		payload = *value
	case *DotNetDLL:
		if value == nil {
			return normalized, invalid("payload", "is nil")
		}
		payload = *value
	case *VBScript:
		if value == nil {
			return normalized, invalid("payload", "is nil")
		}
		payload = *value
	case *JScript:
		if value == nil {
			return normalized, invalid("payload", "is nil")
		}
		payload = *value
	}

	if request.Format > FormatUUID {
		return normalized, invalid("format", fmt.Sprintf("unknown value %d", request.Format))
	}
	if request.Loader.Exit > ExitBlock {
		return normalized, invalid("loader.exit", fmt.Sprintf("unknown value %d", request.Loader.Exit))
	}
	if request.Loader.Entropy > EntropyNone {
		return normalized, invalid("loader.entropy", fmt.Sprintf("unknown value %d", request.Loader.Entropy))
	}

	normalized.format = uint32(request.Format) + 1
	normalized.exit = uint32(request.Loader.Exit) + 1
	if request.Loader.HostContinuation != nil {
		if request.Loader.HostContinuation.EntryPointRVA == 0 {
			return normalized, invalid("loader.hostContinuation.entryPointRVA", "must not be zero")
		}
		normalized.forkRVA = request.Loader.HostContinuation.EntryPointRVA
	}
	normalized.headers = 1
	switch request.Loader.Entropy {
	case EntropyDefault:
		normalized.entropy = 3
	case EntropyNames:
		normalized.entropy = 2
	case EntropyNone:
		normalized.entropy = 1
	}

	switch payload := payload.(type) {
	case NativeExecutable:
		normalized.payload = payload.Image
		normalized.inputName = "fritter-input.exe"
		normalized.expectedType = moduleNativeExecutable
		if unknown := payload.Flags &^ nativeExecutableFlagsMask; unknown != 0 {
			return normalized, invalid("payload.flags", fmt.Sprintf("contains unknown bits 0x%x", uint32(unknown)))
		}
		if payload.Flags&NativeExecutableRunInThread != 0 {
			normalized.thread = 1
		}
		if err := configureNativePE(&normalized, payload.PE); err != nil {
			return normalized, err
		}
	case NativeDLL:
		normalized.payload = payload.Image
		normalized.inputName = "fritter-input.dll"
		normalized.expectedType = moduleNativeDLL
		if payload.Export != nil {
			if err := validateText("payload.export.name", payload.Export.Name, maxConfigStringBytes); err != nil {
				return normalized, err
			}
			if strings.TrimSpace(payload.Export.Name) == "" {
				return normalized, invalid("payload.export.name", "is required")
			}
			normalized.method = payload.Export.Name
		}
		if err := configureNativePE(&normalized, payload.PE); err != nil {
			return normalized, err
		}
	case DotNetExecutable:
		normalized.payload = payload.Assembly
		normalized.inputName = "fritter-input.exe"
		normalized.expectedType = moduleDotNetExecutable
		normalized.runtime = payload.Runtime.Version
		normalized.domain = payload.Runtime.AppDomain
		if err := validateDotNetNames(normalized); err != nil {
			return normalized, err
		}
	case DotNetDLL:
		normalized.payload = payload.Assembly
		normalized.inputName = "fritter-input.dll"
		normalized.expectedType = moduleDotNetDLL
		normalized.class = payload.EntryPoint.TypeName
		normalized.method = payload.EntryPoint.MethodName
		normalized.runtime = payload.Runtime.Version
		normalized.domain = payload.Runtime.AppDomain
		if strings.TrimSpace(normalized.class) == "" {
			return normalized, invalid("payload.entryPoint.typeName", "is required")
		}
		if strings.TrimSpace(normalized.method) == "" {
			return normalized, invalid("payload.entryPoint.methodName", "is required")
		}
		if err := validateDotNetNames(normalized); err != nil {
			return normalized, err
		}
	case VBScript:
		normalized.payload = payload.Source
		normalized.inputName = "fritter-input.vbs"
		normalized.expectedType = moduleVBScript
	case JScript:
		normalized.payload = payload.Source
		normalized.inputName = "fritter-input.js"
		normalized.expectedType = moduleJScript
	default:
		return normalized, invalid("payload", fmt.Sprintf("unsupported type %T", payload))
	}

	if len(normalized.payload) == 0 {
		return normalized, invalid("payload", "is empty")
	}
	if request.Staging != nil {
		server, moduleName, moduleURL, err := normalizeStaging(request.Staging, request.Loader.Entropy)
		if err != nil {
			return normalized, err
		}
		normalized.server = server
		normalized.module = moduleName
		normalized.moduleURL = moduleURL
	}

	return normalized, nil
}

func configureNativePE(normalized *normalizedGeneration, config NativePEConfig) error {
	switch config.Headers {
	case PEHeadersOverwrite:
		normalized.headers = 1
	case PEHeadersPreserve:
		normalized.headers = 2
	default:
		return invalid("payload.pe.headers", fmt.Sprintf("unknown value %d", config.Headers))
	}
	if err := validateText("payload.pe.decoyModulePath", config.DecoyModulePath, maxDecoyPathBytes); err != nil {
		return err
	}
	if config.DecoyModulePath != "" && !isPrintableASCII(config.DecoyModulePath) {
		return invalid("payload.pe.decoyModulePath", "must use printable ASCII")
	}
	normalized.decoy = config.DecoyModulePath
	return nil
}

func validateDotNetNames(generation normalizedGeneration) error {
	fields := []struct {
		name  string
		value string
		max   int
	}{
		{name: "payload.entryPoint.typeName", value: generation.class, max: maxConfigStringBytes},
		{name: "payload.entryPoint.methodName", value: generation.method, max: maxConfigStringBytes},
		{name: "payload.runtime.version", value: generation.runtime, max: maxConfigStringBytes},
		{name: "payload.runtime.appDomain", value: generation.domain, max: maxAppDomainBytes},
	}
	for _, field := range fields {
		if err := validateText(field.name, field.value, field.max); err != nil {
			return err
		}
	}
	return nil
}

func normalizeStaging(staging *HTTPStaging, entropy Entropy) (string, string, *url.URL, error) {
	base := staging.BaseURL
	base.Scheme = strings.ToLower(base.Scheme)
	if base.Scheme != "http" && base.Scheme != "https" {
		return "", "", nil, invalid("staging.baseURL", "scheme must be http or https")
	}
	if base.Host == "" || base.Opaque != "" {
		return "", "", nil, invalid("staging.baseURL", "must be an absolute URL with a host")
	}
	if err := validateStagingHost(base.Host); err != nil {
		return "", "", nil, err
	}
	if strings.ContainsRune(base.Host, '\x00') || strings.ContainsRune(base.Path, '\x00') {
		return "", "", nil, invalid("staging.baseURL", "contains a NUL byte")
	}
	if base.RawQuery != "" || base.ForceQuery {
		return "", "", nil, invalid("staging.baseURL", "must not contain a query")
	}
	if base.Fragment != "" || base.RawFragment != "" {
		return "", "", nil, invalid("staging.baseURL", "must not contain a fragment")
	}
	if base.User != nil {
		username := base.User.Username()
		if !utf8.ValidString(username) || !isPrintableASCII(username) {
			return "", "", nil, invalid("staging.baseURL", "username must use printable ASCII")
		}
		if strings.ContainsRune(username, '\x00') {
			return "", "", nil, invalid("staging.baseURL", "username contains a NUL byte")
		}
		if len(username) > maxHTTPAuthBytes {
			return "", "", nil, invalid("staging.baseURL", fmt.Sprintf("username exceeds %d bytes", maxHTTPAuthBytes))
		}
		if password, present := base.User.Password(); present {
			if !utf8.ValidString(password) || !isPrintableASCII(password) {
				return "", "", nil, invalid("staging.baseURL", "password must use printable ASCII")
			}
			if strings.ContainsRune(password, '\x00') {
				return "", "", nil, invalid("staging.baseURL", "password contains a NUL byte")
			}
			if len(password) > maxHTTPAuthBytes {
				return "", "", nil, invalid("staging.baseURL", fmt.Sprintf("password exceeds %d bytes", maxHTTPAuthBytes))
			}
		}
	}
	if base.RawPath != "" {
		return "", "", nil, invalid("staging.baseURL", "must not contain an explicitly escaped path")
	}
	for _, character := range []byte(base.Path) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '.' || character == '_' ||
			character == '~' || character == '/' {
			continue
		}
		return "", "", nil, invalid("staging.baseURL", "path must use unescaped URL-safe ASCII characters")
	}
	if base.Path == "" {
		base.Path = "/"
	} else if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}

	server := base.String()
	if strings.ContainsRune(server, '\x00') {
		return "", "", nil, invalid("staging.baseURL", "contains a NUL byte")
	}
	for _, character := range []byte(server) {
		if character >= 0x80 {
			return "", "", nil, invalid("staging.baseURL", "must encode to ASCII")
		}
	}
	if len(server) > maxStagingBaseBytes {
		return "", "", nil, invalid("staging.baseURL", fmt.Sprintf("exceeds %d bytes after normalization", maxStagingBaseBytes))
	}

	moduleName := staging.ModuleName
	if moduleName == "" {
		var err error
		moduleName, err = generateModuleName(entropy)
		if err != nil {
			return "", "", nil, fmt.Errorf("generate staging module name: %w", err)
		}
	} else if err := validateModuleName(moduleName); err != nil {
		return "", "", nil, err
	}

	moduleURL, err := url.Parse(server + moduleName)
	if err != nil {
		return "", "", nil, invalid("staging.baseURL", fmt.Sprintf("cannot construct module URL: %v", err))
	}
	return server, moduleName, moduleURL, nil
}

func generateModuleName(entropy Entropy) (string, error) {
	if entropy == EntropyNone {
		return "AAAAAAAA", nil
	}

	const alphabet = "HMN34P67R9TWCXYF"
	random := make([]byte, maxModuleNameBytes)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	for i := range random {
		random[i] = alphabet[int(random[i])%len(alphabet)]
	}
	return string(random), nil
}

func validateModuleName(name string) error {
	if name == "." || name == ".." || len(name) == 0 {
		return invalid("staging.moduleName", "must be a filename")
	}
	if len(name) > maxModuleNameBytes {
		return invalid("staging.moduleName", fmt.Sprintf("exceeds %d bytes", maxModuleNameBytes))
	}
	for _, character := range []byte(name) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '.' || character == '_' || character == '~' {
			continue
		}
		return invalid("staging.moduleName", "contains a character that is unsafe in a URL or filename")
	}
	return nil
}

func validateText(field, value string, maxBytes int) error {
	if !utf8.ValidString(value) {
		return invalid(field, "is not valid UTF-8")
	}
	if strings.ContainsRune(value, '\x00') {
		return invalid(field, "contains a NUL byte")
	}
	if len(value) > maxBytes {
		return invalid(field, fmt.Sprintf("exceeds %d bytes", maxBytes))
	}
	return nil
}

func isPrintableASCII(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

func validateStagingHost(host string) error {
	if !isPrintableASCII(host) {
		return invalid("staging.baseURL", "host must use printable ASCII; use an IDNA hostname when needed")
	}

	hostname := host
	port := ""
	if strings.HasPrefix(host, "[") {
		closing := strings.IndexByte(host, ']')
		if closing < 0 {
			return invalid("staging.baseURL", "contains an invalid IPv6 host")
		}
		hostname = host[1:closing]
		suffix := host[closing+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") || len(suffix) == 1 {
				return invalid("staging.baseURL", "contains an invalid port")
			}
			port = suffix[1:]
		}
		address, err := netip.ParseAddr(hostname)
		if err != nil || !address.Is6() {
			return invalid("staging.baseURL", "contains an invalid IPv6 host")
		}
	} else {
		if strings.Count(host, ":") > 1 {
			return invalid("staging.baseURL", "IPv6 hosts must be enclosed in brackets")
		}
		if before, after, found := strings.Cut(host, ":"); found {
			hostname, port = before, after
			if port == "" {
				return invalid("staging.baseURL", "contains an invalid port")
			}
		}
		if hostname == "" {
			return invalid("staging.baseURL", "must include a hostname")
		}
		if _, err := netip.ParseAddr(hostname); err != nil {
			name := strings.TrimSuffix(hostname, ".")
			if name == "" || len(name) > 253 {
				return invalid("staging.baseURL", "contains an invalid hostname")
			}
			for _, label := range strings.Split(name, ".") {
				if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
					return invalid("staging.baseURL", "contains an invalid hostname")
				}
				for _, character := range []byte(label) {
					if (character >= 'a' && character <= 'z') ||
						(character >= 'A' && character <= 'Z') ||
						(character >= '0' && character <= '9') || character == '-' {
						continue
					}
					return invalid("staging.baseURL", "contains an invalid hostname")
				}
			}
		}
	}

	if port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return invalid("staging.baseURL", "contains an invalid port")
		}
	}
	return nil
}

func invalid(field, problem string) error {
	return &ValidationError{Field: field, Problem: problem}
}
