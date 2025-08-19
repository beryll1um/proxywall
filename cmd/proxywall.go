package main

import (
	"context"
	"net"
	"os"
	"os/signal"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/goccy/go-yaml"
	"golang.org/x/net/proxy"

	"github.com/beryll1um/proxywall/internal/nfso80"

	u "github.com/beryll1um/proxywall/internal/utils"
)

type Config struct {
	NFSO80 *NFSO80Config `yaml:"nfso80,omitempty"`
}

type NFSO80Config struct {
	ListenUrl string `yaml:"listen_url"`
	DialUrl string `yaml:"dial_url"`
	RDNS *RDNSConfig `yaml:"rdns,omitempty"`
}

type RDNSConfig struct {
	RedisMode string `yaml:"redis_mode"`
	RedisUrl string `yaml:"redis_url"`
	Forced  bool `yaml:"forced"`
}

func main() {
	// Lookup for logger level and create instance of it.
	logLvlStr, ok := os.LookupEnv("PROXYWALL_LOGGER_LEVEL")
	if !ok {
		panic("failed to lookup logger level environment variable")
	}
	logLvl, err := logrus.ParseLevel(logLvlStr)
	if err != nil {
		panic("unable to parse logger level")
	}
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logLvl)

	// Lookup for configuration file, read and parse it.
	cfgPath, ok := os.LookupEnv("PROXYWALL_CONFIG_FILE")
	if !ok {
		log.Fatalln("failed to lookup config file  environment variable")
	}
	cfgBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		log.WithError(err).Fatal("failed to read config file:", err)
	}
	cfg := Config{}
	if err := yaml.Unmarshal(cfgBytes, &cfg); err != nil {
		log.WithError(err).Fatal("failed to parse config file:", err)
	}

	if cfg.NFSO80 != nil {
		var resc redis.Cmdable
		// If the NFSO80 RDNS functionality is enabled,
		// we need to connect Redis.
		if cfg.NFSO80.RDNS != nil {
			// Parse and configure Redis connector.
			redisUrl := cfg.NFSO80.RDNS.RedisUrl
			switch cfg.NFSO80.RDNS.RedisMode {
			case "standalone":
				opts, err := redis.ParseURL(redisUrl)
				if err != nil {
					log.WithError(err).Fatal(
						"failed to configure Redis standalone connector")
				}
				resc = redis.NewClient(opts)
			case "cluster":
				opts, err := redis.ParseClusterURL(redisUrl)
				if err != nil {
					log.WithError(err).Fatal(
						"failed to configure Redis cluster connector")
				}
				resc = redis.NewClusterClient(opts)
			}
			if resc != nil {
				if err := resc.Ping(context.TODO()).Err(); err != nil {
					log.WithError(err).Fatal(
						"failed to establish Redis connectivity")
				}
			}
		}

		// Parse and bind proxy server listening address.
		url, err := u.UrlBuilder{Scheme: "tcp"}.String(cfg.NFSO80.ListenUrl)
		if err != nil {
			log.WithError(err).Fatalln("failed to configure proxy listener")
		}
		nfso80Listener, err := net.Listen(url.Scheme, url.Host)
		if err != nil {
			log.WithError(err).Fatalln("failed to setup proxy listener")
		}

		// Parse and configure proxy dialer.
		url, err = u.UrlBuilder{Scheme: "socks5"}.String(cfg.NFSO80.DialUrl)
		if err != nil {
			log.WithError(err).Fatalln("failed to configure proxy dialer")
		}
		nfso80Dialer, err := proxy.FromURL(url, proxy.Direct)
		if err != nil {
			log.WithError(err).Fatalln("failed to setup proxy dialer")
		}

		// Instantiate and start serving NFSO80 server.
		nfso80Server := nfso80.Server{
			Handler: nfso80.Handler{
				Logger: *log.WithField("server", "NFSO80"),
				Resc: resc,
				ForceRDNS: cfg.NFSO80.RDNS.Forced,
			},
			Dialer: nfso80Dialer,
		}
		go func() {
			err := nfso80Server.Serve(nfso80Listener)
			if err != nfso80.ErrServerClosed {
				log.WithError(err).Fatal("failed to serve NFSO80 server")
			}
		}()
		// Defer NFSO80 server shutdown after function completes.
		defer func() {
			if err := nfso80Server.Shutdown(context.TODO()); err != nil {
				log.WithError(err).Fatal("failed to shutdown NFSO80 server")
			}
		}()
	}

	sigIntr := make(chan os.Signal, 1)
	signal.Notify(sigIntr, os.Interrupt)
	<-sigIntr
}

// vim: set ts=4 sw=4 noexpandtab:
