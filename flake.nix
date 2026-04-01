{
  description = "Stardust DHCP server — dev environment and cross-compilation bundles";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;

      # Build a bundle directory containing libssh.a + transitive static deps
      # (libssl.a, libcrypto.a, libz.a) and libssh headers, suitable for
      # passing to zig build -Dlibssh_dir=<path>.
      #
      # `targetPkgs` is a pkgsCross entry (or pkgs itself for the native musl
      # target); we pick .pkgsStatic from it to get musl-linked static .a files.
      mkBundle = targetPkgs:
        let
          sp = targetPkgs.pkgsStatic;
        in
        pkgs.runCommand "libssh-static-bundle" { } ''
          mkdir -p $out/lib $out/include

          cp ${sp.libssh}/lib/libssh.a             $out/lib/
          cp ${sp.openssl.out}/lib/libssl.a         $out/lib/
          cp ${sp.openssl.out}/lib/libcrypto.a      $out/lib/
          cp ${sp.zlib}/lib/libz.a                  $out/lib/

          # Headers are architecture-independent; grab them from the dev output.
          cp -r ${sp.libssh.dev}/include/libssh     $out/include/
        '';
    in
    {
      # Development shell: provides libssh + pkg-config so that
      # `zig build` works without -Dlibssh_dir on a developer workstation.
      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = [ pkgs.libssh pkgs.pkg-config ];
      };

      # Cross-compiled static bundles consumed by the CI release and container
      # workflows via `nix build .#libssh-<arch>-musl --no-link --print-out-paths`.
      packages.x86_64-linux = {
        # Native x86_64-linux-musl
        libssh-x86_64-musl = mkBundle pkgs;
        # Cross-compiled aarch64-linux-musl
        libssh-aarch64-musl = mkBundle pkgs.pkgsCross.aarch64-multiplatform;
        # Cross-compiled riscv64-linux-musl (best-effort; riscv64 musl in nixpkgs
        # is newer and may require a flake.lock refresh if the build fails)
        libssh-riscv64-musl = mkBundle pkgs.pkgsCross.riscv64;
      };
    };
}
