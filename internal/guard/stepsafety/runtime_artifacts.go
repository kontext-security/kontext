package stepsafety

// Official microsoft/onnxruntime release assets. Archive hashes are the
// publisher's GitHub asset digests; library hashes pin the extracted bytes.
// Intel macOS uses 1.23.2, the last upstream x86_64 release asset.
var runtimeArtifacts = map[string]runtimeSpec{
	"darwin/arm64": {Version: "1.24.4", Archive: artifactSpec{Name: "onnxruntime-osx-arm64-1.24.4.tgz", Size: 30937282, SHA256: "93787795f47e1eee369182e43ed51b9e5da0878ab0346aecf4258979b8bba989"}, Library: artifactSpec{Name: "libonnxruntime.1.24.4.dylib", Size: 35418600, SHA256: "872533f130f1839a5bc01788ddb4f75c83a189763441ba1178788ed965449289"}},
	"darwin/amd64": {Version: "1.23.2", Archive: artifactSpec{Name: "onnxruntime-osx-x86_64-1.23.2.tgz", Size: 11676322, SHA256: "d10359e16347b57d9959f7e80a225a5b4a66ed7d7e007274a15cae86836485a6"}, Library: artifactSpec{Name: "libonnxruntime.1.23.2.dylib", Size: 39742608, SHA256: "8c9c78de65ea3786f987c0d980e9c1b13a3a5fbc6b3e2965ba05b450e6e4c054"}},
	"linux/arm64":  {Version: "1.24.4", Archive: artifactSpec{Name: "onnxruntime-linux-aarch64-1.24.4.tgz", Size: 7181958, SHA256: "866109a9248d057671a039b9d725be4bd86888e3754140e6701ec621be9d4d7e"}, Library: artifactSpec{Name: "libonnxruntime.so.1.24.4", Size: 18625376, SHA256: "52b2a0e75e79468404284fec38ad5ee1a7a996232274f5e1b84f3e793fb07554"}},
	"linux/amd64":  {Version: "1.24.4", Archive: artifactSpec{Name: "onnxruntime-linux-x64-1.24.4.tgz", Size: 8155822, SHA256: "3a211fbea252c1e66290658f1b735b772056149f28321e71c308942cdb54b747"}, Library: artifactSpec{Name: "libonnxruntime.so.1.24.4", Size: 22159232, SHA256: "d132535d051344ff5c64c9c200004150559049a81ed330eb4422c1962fb6b7e4"}},
}
