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
	maxArgumentsBytes    = 250
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
	args      string
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
	unicode      uint32
	thread       uint32
	expectedType uint32

	moduleURL *url.URL
}

func normalizeGeneration(payload Payload, optionList []GenerateOption) (normalizedGeneration, error) {
	var normalized normalizedGeneration
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

	options, err := applyGenerateOptions(optionList)
	if err != nil {
		return normalized, err
	}
	if options.format > FormatUUID {
		return normalized, invalid("format", fmt.Sprintf("unknown value %d", options.format))
	}
	if options.exit > ExitBlock {
		return normalized, invalid("exit", fmt.Sprintf("unknown value %d", options.exit))
	}
	if options.entropy > EntropyNone {
		return normalized, invalid("entropy", fmt.Sprintf("unknown value %d", options.entropy))
	}

	normalized.format = uint32(options.format) + 1
	normalized.exit = uint32(options.exit) + 1
	normalized.forkRVA = options.forkRVA
	normalized.headers = 1
	if options.preservePEHeaders {
		normalized.headers = 2
	}
	switch options.entropy {
	case EntropyDefault:
		normalized.entropy = 3
	case EntropyNames:
		normalized.entropy = 2
	case EntropyNone:
		normalized.entropy = 1
	}

	nativePE := false
	payloadName := ""
	switch payload := payload.(type) {
	case NativeExecutable:
		normalized.payload = []byte(payload)
		normalized.inputName = "fritter-input.exe"
		nativePE = true
		normalized.expectedType = moduleNativeExecutable
		payloadName = "native executable"
	case NativeDLL:
		normalized.payload = []byte(payload)
		normalized.inputName = "fritter-input.dll"
		nativePE = true
		normalized.expectedType = moduleNativeDLL
		payloadName = "native DLL"
	case DotNetExecutable:
		normalized.payload = []byte(payload)
		normalized.inputName = "fritter-input.exe"
		normalized.expectedType = moduleDotNetExecutable
		payloadName = ".NET executable"
	case DotNetDLL:
		normalized.payload = []byte(payload)
		normalized.inputName = "fritter-input.dll"
		normalized.expectedType = moduleDotNetDLL
		payloadName = ".NET DLL"
	case VBScript:
		normalized.payload = []byte(payload)
		normalized.inputName = "fritter-input.vbs"
		normalized.expectedType = moduleVBScript
		payloadName = "VBScript"
	case JScript:
		normalized.payload = []byte(payload)
		normalized.inputName = "fritter-input.js"
		normalized.expectedType = moduleJScript
		payloadName = "JScript"
	default:
		return normalized, invalid("payload", fmt.Sprintf("unsupported type %T", payload))
	}

	if len(normalized.payload) == 0 {
		return normalized, invalid("payload", "is empty")
	}
	if err := configureInvocation(&normalized, options, payloadName); err != nil {
		return normalized, err
	}

	if !nativePE {
		switch {
		case options.preservePEHeaders:
			return normalized, invalid("preservePEHeaders", "is only supported for native PE payloads")
		case options.decoyModulePath != "":
			return normalized, invalid("decoyModulePath", "is only supported for native PE payloads")
		}
	}

	if err := validateText("decoyModulePath", options.decoyModulePath, maxDecoyPathBytes); err != nil {
		return normalized, err
	}
	normalized.decoy = options.decoyModulePath

	if options.staging != nil {
		server, moduleName, moduleURL, err := normalizeStaging(options.staging, options.entropy)
		if err != nil {
			return normalized, err
		}
		normalized.server = server
		normalized.module = moduleName
		normalized.moduleURL = moduleURL
	}

	return normalized, nil
}

func configureInvocation(normalized *normalizedGeneration, options generationOptions, payloadName string) error {
	kind := normalized.expectedType
	compatibility := []struct {
		field   string
		set     bool
		allowed bool
	}{
		{field: "arguments", set: options.argumentsSet, allowed: kind == moduleNativeExecutable || kind == moduleDotNetExecutable || kind == moduleDotNetDLL},
		{field: "runInThread", set: options.runInThread, allowed: kind == moduleNativeExecutable},
		{field: "export", set: options.exportSet, allowed: kind == moduleNativeDLL},
		{field: "parameter", set: options.parameterSet, allowed: kind == moduleNativeDLL},
		{field: "method", set: options.methodSet, allowed: kind == moduleDotNetDLL},
		{field: "runtimeVersion", set: options.runtimeSet, allowed: kind == moduleDotNetExecutable || kind == moduleDotNetDLL},
		{field: "appDomain", set: options.appDomainSet, allowed: kind == moduleDotNetExecutable || kind == moduleDotNetDLL},
	}
	for _, option := range compatibility {
		if option.set && !option.allowed {
			return invalid(option.field, fmt.Sprintf("is not supported for %s payloads", payloadName))
		}
	}

	switch kind {
	case moduleNativeExecutable:
		arguments, err := encodeArguments(options.arguments)
		if err != nil {
			return err
		}
		normalized.args = arguments
		if options.runInThread {
			normalized.thread = 1
		}
	case moduleNativeDLL:
		if err := validateText("export", options.export, maxConfigStringBytes); err != nil {
			return err
		}
		if err := validateText("parameter", options.parameter, maxArgumentsBytes); err != nil {
			return err
		}
		if options.parameterSet && options.parameter == "" {
			return invalid("parameter", "must not be empty")
		}
		if options.parameter != "" && options.export == "" {
			return invalid("export", "is required when a DLL parameter is supplied")
		}
		normalized.method = options.export
		normalized.args = options.parameter
		if options.parameterUTF16 {
			normalized.unicode = 1
		}
	case moduleDotNetExecutable, moduleDotNetDLL:
		arguments, err := encodeArguments(options.arguments)
		if err != nil {
			return err
		}
		normalized.args = arguments
		normalized.class = options.class
		normalized.method = options.method
		normalized.runtime = options.runtimeVersion
		normalized.domain = options.appDomain
		if kind == moduleDotNetDLL {
			if strings.TrimSpace(options.class) == "" {
				return invalid("class", "is required")
			}
			if strings.TrimSpace(options.method) == "" {
				return invalid("method", "is required")
			}
		}
		if err := validateDotNetNames(*normalized); err != nil {
			return err
		}
	}
	return nil
}

func validateDotNetNames(generation normalizedGeneration) error {
	fields := []struct {
		name  string
		value string
		max   int
	}{
		{name: "class", value: generation.class, max: maxConfigStringBytes},
		{name: "method", value: generation.method, max: maxConfigStringBytes},
		{name: "runtimeVersion", value: generation.runtime, max: maxConfigStringBytes},
		{name: "appDomain", value: generation.domain, max: maxAppDomainBytes},
	}
	for _, field := range fields {
		if err := validateText(field.name, field.value, field.max); err != nil {
			return err
		}
	}
	return nil
}

func normalizeStaging(staging *httpStagingOptions, entropy Entropy) (string, string, *url.URL, error) {
	if staging.baseURL == nil {
		return "", "", nil, invalid("staging.baseURL", "is required")
	}

	base := *staging.baseURL
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

	moduleName := staging.moduleName
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
