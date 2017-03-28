package conf

import (
	"flag"
	"os"

	"github.com/BurntSushi/toml"
)

// Conf global variable.
var (
	Conf     *Config
	confPath string
)

type Config struct {
	Version    string
	AuthServer string
	Port       string
	Username   string
	Password   string
	Hostname   string
	Mac        string
	Ip         string
}

func init() {
	flag.StringVar(&confPath, "conf", "", "default config path")
}

// Init create config instance.
func Init() (err error) {
	if confPath == "" {
		confPath = "drcom-config-example.toml"
	}
	if _, err = toml.DecodeFile(confPath, &Conf); err != nil {
		return
	}
	if Conf.Hostname, err = os.Hostname(); err != nil {
		Conf.Hostname = "unknown"
	}
	return
}
