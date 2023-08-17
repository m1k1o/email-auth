package main

import (
	_ "time/tzdata"

	"github.com/m1k1o/email-auth/cmd"
)

var (
	version = ""

	buildDate = "dev"
	gitCommit = "dev"
	gitBranch = "dev"
)

func init() {
	cmd.ProgramName = "email-auth"
	cmd.ProgramDesc = "Authentication using email."

	cmd.Init(cmd.Version{
		Version: version,

		BuildDate: buildDate,
		GitCommit: gitCommit,
		GitBranch: gitBranch,
	})
}

func main() {
	_ = cmd.Execute()
}
