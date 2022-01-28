package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/m1k1o/email-auth/internal/config"
	"github.com/m1k1o/email-auth/internal/mail"
)

func init() {
	var config config.Email

	command := &cobra.Command{
		Use:   "test",
		Short: "Test your SMTP setup.",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				log.Error().Msg("please specify your target email as an argument")
				return
			}

			toEmail := args[0]

			err := mail.Test(config, toEmail)
			if err != nil {
				log.Panic().Err(err).Msg("unable to start test command")
			}
		},
	}

	onInitialize = append(onInitialize, config.Set)

	if err := config.Init(command); err != nil {
		log.Panic().Err(err).Msg("unable to init configuration")
	}

	rootCmd.AddCommand(command)
}
