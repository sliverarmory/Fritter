package fritter

import (
	"fmt"
	"net/url"
)

// GenerateOption configures one Generate call. Its zero value is invalid; use
// the option constructors in this package.
type GenerateOption struct {
	apply func(*generationOptions) error
}

// HTTPStagingOption configures WithHTTPStaging. Its zero value is invalid; use
// WithStagedModuleName to construct one.
type HTTPStagingOption struct {
	apply func(*httpStagingOptions) error
}

type generationOptions struct {
	format            Format
	exit              ExitBehavior
	forkRVA           uint32
	entropy           Entropy
	preservePEHeaders bool
	decoyModulePath   string
	staging           *httpStagingOptions
}

type httpStagingOptions struct {
	baseURL    *url.URL
	moduleName string
}

// WithFormat selects the representation returned in Result.Loader.
func WithFormat(format Format) GenerateOption {
	return GenerateOption{apply: func(options *generationOptions) error {
		options.format = format
		return nil
	}}
}

// WithExit selects what the loader does after the payload returns.
func WithExit(exit ExitBehavior) GenerateOption {
	return GenerateOption{apply: func(options *generationOptions) error {
		options.exit = exit
		return nil
	}}
}

// WithForkRVA runs the payload on a new thread and resumes the host image at
// the supplied relative virtual address.
func WithForkRVA(rva uint32) GenerateOption {
	return GenerateOption{apply: func(options *generationOptions) error {
		options.forkRVA = rva
		return nil
	}}
}

// WithEntropy selects the optional per-output randomization mode.
func WithEntropy(entropy Entropy) GenerateOption {
	return GenerateOption{apply: func(options *generationOptions) error {
		options.entropy = entropy
		return nil
	}}
}

// PreservePEHeaders keeps the mapped payload's PE headers. It is valid only
// for native PE payloads.
func PreservePEHeaders() GenerateOption {
	return GenerateOption{apply: func(options *generationOptions) error {
		options.preservePEHeaders = true
		return nil
	}}
}

// WithDecoyModulePath embeds the exact target-side Windows path used for
// module overloading. The Go package does not read or inspect the path.
func WithDecoyModulePath(path string) GenerateOption {
	return GenerateOption{apply: func(options *generationOptions) error {
		options.decoyModulePath = path
		return nil
	}}
}

// WithHTTPStaging returns the payload module separately from the loader. The
// package embeds baseURL in the loader but performs no upload or network call.
func WithHTTPStaging(baseURL *url.URL, stagingOptions ...HTTPStagingOption) GenerateOption {
	var clonedURL *url.URL
	if baseURL != nil {
		clone := *baseURL
		clonedURL = &clone
	}
	clonedOptions := append([]HTTPStagingOption(nil), stagingOptions...)

	return GenerateOption{apply: func(options *generationOptions) error {
		staging := &httpStagingOptions{baseURL: clonedURL}
		for index, option := range clonedOptions {
			if option.apply == nil {
				return invalid(fmt.Sprintf("staging.options[%d]", index), "is the zero value")
			}
			if err := option.apply(staging); err != nil {
				return err
			}
		}
		options.staging = staging
		return nil
	}}
}

// WithStagedModuleName sets the staged module's URL-safe filename. When this
// option is omitted, Fritter generates an eight-character name.
func WithStagedModuleName(name string) HTTPStagingOption {
	return HTTPStagingOption{apply: func(options *httpStagingOptions) error {
		options.moduleName = name
		return nil
	}}
}

func applyGenerateOptions(optionList []GenerateOption) (generationOptions, error) {
	var options generationOptions
	for index, option := range optionList {
		if option.apply == nil {
			return generationOptions{}, invalid(fmt.Sprintf("options[%d]", index), "is the zero value")
		}
		if err := option.apply(&options); err != nil {
			return generationOptions{}, err
		}
	}
	return options, nil
}
