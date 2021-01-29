package main

import (
	"github.com/spf13/viper"
)

type Config struct {
	Iface   string               `mapstructure:"iface"`
	XdpProg string               `mapstructure:"xdp_prog"`
	SID     map[string]SidConfig `mapstructure:"sid"`
	DNat    []DnatConfig         `mapstructure:"dnat"`
}

type SidConfig struct {
	Dnat       bool `mapstructure:"dst"`
	Masquerade bool `mapstructure:"masquerade"`
}

type DnatConfig struct {
	Dst    string `mapstructure:"dst"`
	Port   uint16 `mapstructure:"port"`
	ToDst  string `mapstructure:"to_dst"`
	ToPort uint16 `mapstructure:"to_port"`
}

var config Config

func init() {
	viper.SetConfigName("config.yml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/mptcp-proxy/")
	viper.AddConfigPath("$HOME/.mptcp-proxy")
	viper.AddConfigPath(".")

	viper.SetDefault("iface", "eth0")
	viper.SetDefault("xdp_prog", "nfNat_dp.o")

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}
	if err := viper.Unmarshal(&config); err != nil {
		panic(err)
	}
}
