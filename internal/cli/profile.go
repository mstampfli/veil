package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/chain"
	"github.com/mstampfli/veil/internal/profile"
)

// ProfileCmd groups profile management subcommands.
func ProfileCmd() *cobra.Command {
	c := &cobra.Command{Use: "profile", Short: "Manage profiles"}
	c.AddCommand(profileNewCmd(), profileShowCmd(), profileDeleteCmd(),
		profileExportCmd(), profileImportCmd(),
		profileImportWGCmd(), profileImportOVPNCmd(),
		profileImportMullvadCmd(), profileImportProtonCmd(), profileImportIVPNCmd(),
		profileDriftCmd(), profileProbeCmd())
	return c
}

func profileImportMullvadCmd() *cobra.Command {
	var dir, preset string
	var ks bool
	c := &cobra.Command{
		Use:   "import-mullvad [dir]",
		Short: "Import Mullvad WireGuard configs (one profile per server)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			if len(args) == 1 {
				dir = args[0]
			}
			created, err := s.ImportMullvad(dir, preset, ks)
			printCreated(created, err)
			return err
		},
	}
	c.Flags().StringVar(&preset, "preset", "firefox", "default app preset")
	c.Flags().BoolVar(&ks, "kill-switch", true, "enable kill switch")
	return c
}

func profileImportProtonCmd() *cobra.Command {
	var preset string
	var ks bool
	c := &cobra.Command{
		Use:   "import-proton <dir>",
		Short: "Import ProtonVPN WireGuard configs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			created, err := s.ImportProton(args[0], preset, ks)
			printCreated(created, err)
			return err
		},
	}
	c.Flags().StringVar(&preset, "preset", "firefox", "default app preset")
	c.Flags().BoolVar(&ks, "kill-switch", true, "enable kill switch")
	return c
}

func profileImportIVPNCmd() *cobra.Command {
	var preset string
	var ks bool
	c := &cobra.Command{
		Use:   "import-ivpn <dir>",
		Short: "Import IVPN WireGuard configs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			created, err := s.ImportIVPN(args[0], preset, ks)
			printCreated(created, err)
			return err
		},
	}
	c.Flags().StringVar(&preset, "preset", "firefox", "default app preset")
	c.Flags().BoolVar(&ks, "kill-switch", true, "enable kill switch")
	return c
}

func printCreated(names []string, err error) {
	for _, n := range names {
		fmt.Println("created", n)
	}
	if err == nil {
		fmt.Printf("(%d profiles)\n", len(names))
	}
}

func profileImportWGCmd() *cobra.Command {
	var preset, dataRoot string
	var killSwitch bool
	c := &cobra.Command{
		Use:   "import-wg <dir-or-file>",
		Short: "Bulk-import WireGuard .conf files (one profile per file)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			created, err := s.BulkImportWG(args[0], preset, dataRoot, killSwitch)
			if err != nil {
				return err
			}
			for _, n := range created {
				fmt.Println("created", n)
			}
			fmt.Printf("(%d profiles)\n", len(created))
			return nil
		},
	}
	c.Flags().StringVar(&preset, "preset", "firefox", "default app preset for new profiles")
	c.Flags().StringVar(&dataRoot, "data-dir-root", "", "if set, each profile gets <root>/<name> as its isolated data dir")
	c.Flags().BoolVar(&killSwitch, "kill-switch", true, "enable kill switch for new profiles")
	return c
}

func profileImportOVPNCmd() *cobra.Command {
	var preset, dataRoot string
	var killSwitch bool
	c := &cobra.Command{
		Use:   "import-ovpn <dir-or-file>",
		Short: "Bulk-import OpenVPN .ovpn files (one profile per file)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			created, err := s.BulkImportOVPN(args[0], preset, dataRoot, killSwitch)
			if err != nil {
				return err
			}
			for _, n := range created {
				fmt.Println("created", n)
			}
			fmt.Printf("(%d profiles)\n", len(created))
			return nil
		},
	}
	c.Flags().StringVar(&preset, "preset", "firefox", "default app preset for new profiles")
	c.Flags().StringVar(&dataRoot, "data-dir-root", "", "if set, each profile gets <root>/<name> as its isolated data dir")
	c.Flags().BoolVar(&killSwitch, "kill-switch", true, "enable kill switch for new profiles")
	return c
}

func profileNewCmd() *cobra.Command {
	var (
		preset, binary, dataDir string
		backend                 string
		host                    string
		port                    int
		user, pass              string
		configPath              string
		dns                     []string
		killSwitch              bool
		args                    []string
	)
	cmd := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a new profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, cmdArgs []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			b := profile.Backend{Kind: profile.BackendKind(backend)}
			switch b.Kind {
			case profile.BackendSOCKS5, profile.BackendHTTP:
				b.Host = host
				b.Port = port
				b.Username = user
				b.Password = pass
			case profile.BackendWireGuard, profile.BackendOpenVPN:
				b.ConfigPath = configPath
			}
			p := &profile.Profile{
				Name:       cmdArgs[0],
				Chain:      []profile.Backend{b},
				DNS:        dns,
				KillSwitch: killSwitch,
				DataDir:    dataDir,
				App: profile.App{
					Preset: preset,
					Binary: binary,
					Args:   args,
				},
			}
			if err := chain.Validate(p.Chain); err != nil {
				return err
			}
			if err := s.Save(p); err != nil {
				return err
			}
			fmt.Printf("Created profile %s\n", p.Name)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&backend, "backend", "direct", "backend kind: direct|socks5|http|wireguard|openvpn|tor")
	f.StringVar(&host, "host", "", "proxy host")
	f.IntVar(&port, "port", 0, "proxy port")
	f.StringVar(&user, "user", "", "proxy username")
	f.StringVar(&pass, "pass", "", "proxy password")
	f.StringVar(&configPath, "config", "", "wireguard/openvpn config path")
	f.StringSliceVar(&dns, "dns", nil, "DNS servers")
	f.BoolVar(&killSwitch, "kill-switch", true, "fail-closed kill switch")
	f.StringVar(&preset, "preset", "", "app preset (firefox|chromium|brave|signal|telegram|shell|curl)")
	f.StringVar(&binary, "binary", "", "app binary path (overrides preset)")
	f.StringVar(&dataDir, "data-dir", "", "isolated data directory for the app")
	f.StringSliceVar(&args, "arg", nil, "extra args to the app (repeatable)")
	return cmd
}

func profileShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a profile's full configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			p, err := s.Load(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Name:           %s\nDescription:    %s\nChain:          %d hop(s)\nApp:            %s (%s)\n",
				p.Name, p.Description, len(p.Chain), p.App.Preset, p.App.Binary)
			afDisplay := "off"
			if p.AntiFingerprint.IsOn() {
				afDisplay = string(p.AntiFingerprint)
			}
			fmt.Printf("KillSwitch:     %v\nAntiFingerprint: %s\nPersona:        %s\nForgePersona:   %v\n",
				p.KillSwitch, afDisplay, p.Persona, p.ForgePersona)
			if p.LockedEndpoint {
				fmt.Printf("LockedEndpoint: yes (country=%s city=%s asn=%s ip=%s)\n",
					p.RequireExitCountry, p.RequireExitCity, p.RequireExitASN, p.RequireExitIP)
			}
			if p.ScheduleWindow != "" {
				fmt.Printf("ScheduleWindow: %s (persona TZ)\n", p.ScheduleWindow)
			}
			if p.BehavioralJitter || p.MouseJitter {
				fmt.Printf("Behavioral:     keyboard=%v mouse=%v\n", p.BehavioralJitter, p.MouseJitter)
			}
			if p.TCPPersona != "" {
				fmt.Printf("TCPPersona:     %s\n", p.TCPPersona)
			}
			return nil
		},
	}
}

func profileDeleteCmd() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			if !force {
				fmt.Printf("Delete profile %q? [y/N] ", args[0])
				rd := bufio.NewReader(os.Stdin)
				ans, _ := rd.ReadString('\n')
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "y") {
					return nil
				}
			}
			return s.Delete(args[0])
		},
	}
	c.Flags().BoolVarP(&force, "force", "f", false, "skip confirmation")
	return c
}

func profileExportCmd() *cobra.Command {
	var pass string
	c := &cobra.Command{
		Use:   "export <name> <file>",
		Short: "Export a profile to an age-encrypted file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			p, err := s.Load(args[0])
			if err != nil {
				return err
			}
			if pass == "" {
				fmt.Print("Passphrase: ")
				rd := bufio.NewReader(os.Stdin)
				pass, _ = rd.ReadString('\n')
				pass = strings.TrimSpace(pass)
			}
			f, err := os.Create(args[1])
			if err != nil {
				return err
			}
			defer f.Close()
			return profile.Export(p, pass, f)
		},
	}
	c.Flags().StringVar(&pass, "passphrase", "", "passphrase (insecure on cmdline; prompt if empty)")
	return c
}

func profileImportCmd() *cobra.Command {
	var pass string
	c := &cobra.Command{
		Use:   "import <file>",
		Short: "Import an age-encrypted profile bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			if pass == "" {
				fmt.Print("Passphrase: ")
				rd := bufio.NewReader(os.Stdin)
				pass, _ = rd.ReadString('\n')
				pass = strings.TrimSpace(pass)
			}
			p, err := profile.Import(pass, f)
			if err != nil {
				return err
			}
			if err := chain.Validate(p.Chain); err != nil {
				return err
			}
			if err := s.Save(p); err != nil {
				return err
			}
			fmt.Printf("Imported %s\n", p.Name)
			return nil
		},
	}
	c.Flags().StringVar(&pass, "passphrase", "", "passphrase (insecure on cmdline; prompt if empty)")
	return c
}
