{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "digdeep-dev-shell";

  buildInputs = with pkgs; [
    nodejs_22
    dnsutils # dig, delv, nslookup for CLI DNS/DNSSEC inspection
  ];

  shellHook = ''
    export PATH="$PWD/node_modules/.bin:$PATH"

    if [ ! -d "node_modules" ]; then
      echo "Installing npm dependencies..."
      npm install
    fi

    echo ""
    echo "DigDeep development environment ready (Node $(node --version), npm $(npm --version))"
    echo "Commands:"
    echo "  npm run dev        - Start Vite development server"
    echo "  npm test           - Run Vitest test suite"
    echo "  npm run test:watch - Run Vitest in watch mode"
    echo "  npm run build      - Type-check and build for production"
    echo "  npm run preview    - Preview production build"
  '';
}
