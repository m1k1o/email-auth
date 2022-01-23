package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"email-proxy-auth/internal"
	"email-proxy-auth/internal/config"
)

func init() {
	var config config.Serve

	command := &cobra.Command{
		Use:   "serve",
		Short: "Start HTTP server.",
		Run: func(cmd *cobra.Command, args []string) {
			err := internal.Serve(config)
			if err != nil {
				log.Panic().Err(err).Msg("unable to start serve command")
			}
		},
	}

	onInitialize = append(onInitialize, config.Set)

	if err := config.Init(command); err != nil {
		log.Panic().Err(err).Msg("unable to init configuration")
	}

	rootCmd.AddCommand(command)
}
