package config

import (
	"github.com/spf13/cobra"
)

type Serve struct {
	App    App
	Tmpl   Tmpl
	Email  Email
	Cookie Cookie
	Redis  Redis
	Gui    Gui
}

func (c *Serve) Init(cmd *cobra.Command) error {
	if err := c.App.Init(cmd); err != nil {
		return err
	}

	if err := c.Tmpl.Init(cmd); err != nil {
		return err
	}

	if err := c.Email.Init(cmd); err != nil {
		return err
	}

	if err := c.Cookie.Init(cmd); err != nil {
		return err
	}

	if err := c.Redis.Init(cmd); err != nil {
		return err
	}

	if err := c.Gui.Init(cmd); err != nil {
		return err
	}

	return nil
}

func (c *Serve) Set() {
	c.App.Set()
	c.Tmpl.Set()
	c.Email.Set()
	c.Cookie.Set()
	c.Redis.Set()
	c.Gui.Set()
}
