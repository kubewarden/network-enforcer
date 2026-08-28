package flowdumper

const (
	// DefaultBufferSize is the default size of the buffer used by the flow dumper.
	DefaultBufferSize = 2000
	// DefaultPort is the default port used by the flow dumper HTTP server.
	DefaultPort = 9080
)

type Config struct {
	Enabled    bool
	BufferSize int
	Port       int
}
