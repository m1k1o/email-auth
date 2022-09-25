// go-base version 2.2.2
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	ProgramName = "go-base"
	ProgramDesc = "Default program description."

	ConfigPath = ""
	EnvPrefix  = "CONF"
)

var rootCmd = &cobra.Command{}
var onInitialize []func()

func Init(v Version) {
	rootCmd.Use = ProgramName
	rootCmd.Short = ProgramDesc
	rootCmd.Version = v.String()
	rootCmd.SetVersionTemplate(v.Details())

	// use default config path
	if ConfigPath == "" {
		ConfigPath = path.Join("/etc/", ProgramName)
	}

	var cfgFile string
	var logConfig logConfig

	cobra.OnInitialize(func() {
		confs := initConfiguration(cfgFile, ConfigPath, EnvPrefix)
		logConfig.Set()
		initLogging(logConfig)

		// display version
		log.Debug().Msgf("starting %s, version %s", rootCmd.Use, rootCmd.Version)

		// display used configuration files
		for _, conf := range confs {
			log.Debug().Str("config", conf).Msg("preflight complete with config file")
		}
		if len(confs) == 0 {
			log.Debug().Msg("preflight complete without config file")
		}

		// call initialization functions
		for _, fn := range onInitialize {
			fn()
		}
	})

	// config file
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "configuration file path")
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))

	// log configuration
	_ = logConfig.Init(rootCmd)
}

type Config interface {
	Init(cmd *cobra.Command) error
	Set()
}

func Execute() error {
	return rootCmd.Execute()
}

//
// Version
//

type Version struct {
	Version string

	GitCommit string
	GitBranch string
	BuildDate string
}

func (v *Version) HasVersion() bool {
	return strings.HasPrefix(v.Version, "v")
}

func (v *Version) String() string {
	// ignore if it is unsubstituted variable or empty
	version := v.Version
	if !v.HasVersion() {
		version = v.GitBranch
	}

	// use only git shot tag
	commit := v.GitCommit
	if len(commit) > 7 {
		commit = commit[:7]
	}

	return fmt.Sprintf("%s@%s", version, commit)
}

func (v *Version) Details() string {
	lines := []string{}

	if v.HasVersion() {
		lines = append(lines, fmt.Sprintf("Version %s", v.Version))
	}

	return strings.Join(append(lines,
		fmt.Sprintf("GitCommit %s", v.GitCommit),
		fmt.Sprintf("GitBranch %s", v.GitBranch),
		fmt.Sprintf("BuildDate %s", v.BuildDate),
		fmt.Sprintf("GoVersion %s", runtime.Version()),
		fmt.Sprintf("Compiler %s", runtime.Compiler),
		fmt.Sprintf("Platform %s/%s", runtime.GOOS, runtime.GOARCH),
	), "\n") + "\n"
}

//
// Configuration initialization
//

func initConfiguration(cfgFile string, defCfgPath string, envPrefix string) []string {
	// use configuration file if provided
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// confguration file name
		viper.SetConfigName("config")

		// search for configuration file
		if runtime.GOOS == "linux" && defCfgPath != "" {
			viper.AddConfigPath(defCfgPath)
		}

		// seatch for configuration file in ./
		viper.AddConfigPath(".")
	}

	if envPrefix != "" {
		// env prefix is uppercase progname
		viper.SetEnvPrefix(envPrefix)

		// replace . and - with _
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

		// read in environment variables that match
		viper.AutomaticEnv()
	}

	var configs []string

	// read config file
	err := viper.ReadInConfig()
	if file := viper.ConfigFileUsed(); file != "" {
		if err != nil {
			panic(fmt.Errorf("fatal error config file %q: %w", file, err))
		}
		configs = append(configs, file)
	}

	// merge in config file from env
	env := os.Getenv(envPrefix + "_CONFIG")
	if env != "" {
		viper.SetConfigFile(env)
		err := viper.MergeInConfig()

		if file := viper.ConfigFileUsed(); file != "" {
			if err != nil {
				panic(fmt.Errorf("fatal error config file %q: %w", file, err))
			}
			configs = append(configs, file)
		}
	}

	return configs
}

//
// Logging initialization
//

type logConfig struct {
	// Set log level
	Level string
	// Set log ci
	Ci string
	// Output logs in JSON format
	Json bool

	// Enable console logging
	Console bool

	// Enable file logging and specify its path
	File string
	// MaxAge the max age in days to keep a logfile
	MaxAge int
	// MaxSize the max size in MB of the logfile before it's rolled
	MaxSize int
	// MaxBackups the max number of rolled files to keep
	MaxBackups int
}

func (logConfig) Init(cmd *cobra.Command) error {
	cmd.PersistentFlags().String("log.level", "", "Set log level")
	if err := viper.BindPFlag("log.level", cmd.PersistentFlags().Lookup("log.level")); err != nil {
		return err
	}

	cmd.PersistentFlags().String("log.ci", "", "Set log ci")
	if err := viper.BindPFlag("log.ci", cmd.PersistentFlags().Lookup("log.ci")); err != nil {
		return err
	}

	cmd.PersistentFlags().Bool("log.json", false, "Output logs in JSON format")
	if err := viper.BindPFlag("log.json", cmd.PersistentFlags().Lookup("log.json")); err != nil {
		return err
	}

	// console

	cmd.PersistentFlags().Bool("log.console", false, "Enable console logging")
	if err := viper.BindPFlag("log.console", cmd.PersistentFlags().Lookup("log.console")); err != nil {
		return err
	}

	// file

	cmd.PersistentFlags().String("log.file", "", "Enable file logging and specify its path")
	if err := viper.BindPFlag("log.file", cmd.PersistentFlags().Lookup("log.file")); err != nil {
		return err
	}

	cmd.PersistentFlags().Int("log.maxage", 0, "MaxAge the max age in days to keep a logfile")
	if err := viper.BindPFlag("log.maxage", cmd.PersistentFlags().Lookup("log.maxage")); err != nil {
		return err
	}

	cmd.PersistentFlags().Int("log.maxsize", 0, "MaxSize the max size in MB of the logfile before it's rolled")
	if err := viper.BindPFlag("log.maxsize", cmd.PersistentFlags().Lookup("log.maxsize")); err != nil {
		return err
	}

	cmd.PersistentFlags().Int("log.maxbackups", 0, "MaxBackups the max number of rolled files to keep")
	if err := viper.BindPFlag("log.maxbackups", cmd.PersistentFlags().Lookup("log.maxbackups")); err != nil {
		return err
	}

	return nil
}

func (c *logConfig) Set() {
	c.Level = viper.GetString("log.level")
	c.Ci = viper.GetString("log.ci")
	c.Json = viper.GetBool("log.json")

	c.Console = viper.GetBool("log.console")

	c.File = viper.GetString("log.file")
	c.MaxAge = viper.GetInt("log.maxage")
	c.MaxSize = viper.GetInt("log.maxsize")
	c.MaxBackups = viper.GetInt("log.maxbackups")

	// use by default console if no file
	if c.File == "" {
		c.Console = true
	}

	// there is not normal level, it is info
	if c.Level == "normal" {
		c.Level = "info"
	}
}

func logWriter(out io.Writer, config logConfig) io.Writer {
	// if json, return unchanged io writer
	if config.Json {
		return out
	}

	// if no ci, return unchanged console writer
	if config.Ci == "" {
		return zerolog.ConsoleWriter{
			Out: out,
		}
	}

	// if file, return unchanged console writer
	return zerolog.ConsoleWriter{
		Out:     out,
		NoColor: true,
		FormatTimestamp: func(i interface{}) string {
			if tt, ok := i.(json.Number); ok {
				i, err := tt.Int64()
				if err != nil {
					return tt.String()
				}
				var sec, nsec int64 = i, 0
				ts := time.Unix(sec, nsec)
				return ts.Format("2006-01-02 15:04:05")
			}
			return "<nil>"
		},
		FormatLevel: func(i interface{}) string {
			level := "- "
			if i == nil {
				level += "???"
			} else if ll, ok := i.(string); ok {
				switch ll {
				case zerolog.LevelTraceValue:
					level += "TRACE"
				case zerolog.LevelDebugValue:
					level += "DEBUG"
				case zerolog.LevelInfoValue:
					level += "NORMAL" // OSS
				case zerolog.LevelWarnValue:
					level += "WARNING" // OSS
				case zerolog.LevelErrorValue, zerolog.LevelFatalValue:
					level += "ERROR" // OSS
				case zerolog.LevelPanicValue:
					level += "PANIC"
				default:
					level += "???"
				}
			} else {
				level += strings.ToUpper(fmt.Sprintf("%s", i))
			}

			if config.Ci != "" {
				level += " - " + config.Ci
			}

			return level + " -"
		},
		FormatCaller: func(i interface{}) string {
			if ci, ok := i.(string); ok && len(ci) > 0 {
				return ci + " -"
			}
			return ""
		},
	}
}

func initLogging(config logConfig) {
	var writers []io.Writer

	if config.Console {
		writers = append(writers, logWriter(os.Stderr, config))
	}

	if config.File != "" {
		logger := &lumberjack.Logger{
			Filename:   config.File,
			MaxAge:     config.MaxAge,     // days
			MaxSize:    config.MaxSize,    // megabytes
			MaxBackups: config.MaxBackups, // files
		}

		// rotate in response to SIGHUP
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)

		go func() {
			for {
				<-c
				logger.Rotate()
			}
		}()

		writers = append(writers, logWriter(logger, config))
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(io.MultiWriter(writers...))

	// only if using json, append ci
	if config.Json && config.Ci != "" {
		log.Logger = log.With().Str("ci", config.Ci).Logger()
	}

	if config.Level == "" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("using default log level")
	} else {
		// set custom log level
		level, err := zerolog.ParseLevel(config.Level)
		if err != nil {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
			log.Debug().Str("log-level", config.Level).Msg("unknown log level")
		} else {
			zerolog.SetGlobalLevel(level)
		}
	}

	log.Debug().
		Bool("console", config.Console).
		Str("file", config.File).
		Int("maxage", config.MaxAge).
		Int("maxsize", config.MaxSize).
		Int("maxbackups", config.MaxBackups).
		Msg("logging configured")
}
