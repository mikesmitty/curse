package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

func pwauth(conf *config, user, pass string) (bool, error) {
	// Build our timeout context
	ctx, cancel := context.WithTimeout(context.Background(), conf.authTimeout)
	defer cancel()

	// Build our command with context for timeout
	cmd := exec.CommandContext(ctx, conf.Pwauth)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, fmt.Errorf("failed to open stdin to pwauth: %v", err)
	}

	// Run pwauth
	err = cmd.Start()
	if err != nil {
		return false, fmt.Errorf("failed to start pwauth: %v", err)
	}
	// Send the user/pass over stdin
	_, err = io.WriteString(stdin, fmt.Sprintf("%s\n%s\n", user, pass))
	if err != nil {
		return false, fmt.Errorf("failed to pass username/password to pwauth: %v", err)
	}
	// Wait for pwauth to complete
	err = cmd.Wait()
	if err != nil {
		return false, fmt.Errorf("pwauth failed: %v", err)
	}

	return true, nil
}

func unixgroup(conf *config, user, principal string) error {
	// If this is a wildcard ACL, allow immediately
	groups := conf.principalMap[principal]
	if groups == "*" {
		return nil
	} else if groups == "" {
		return fmt.Errorf("unknown principal: %s", principal)
	}

	// Build our timeout context
	ctx, cancel := context.WithTimeout(context.Background(), conf.authTimeout)
	defer cancel()

	// Build our command with context for timeout
	cmd := exec.CommandContext(ctx, conf.Unixgroup)

	// Set our env variables
	cmd.Env = append(cmd.Env, fmt.Sprintf("USER=%s", user))
	cmd.Env = append(cmd.Env, fmt.Sprintf("GROUP=%s", groups))

	// Run unixgroup
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("invalid groups or unixgroup command error: (user: %s) %v", user, err)
	}

	return nil
}
