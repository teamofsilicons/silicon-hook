import { defineConfig, loadEnv } from "vite";
import solid from "vite-plugin-solid";
import { Server } from "node:http";
import { config, gateway } from "./server/gateway.ts";
export default defineConfig(({ mode }) => {
  const cfg = config({
    ...loadEnv(mode, process.cwd(), ""),
    ...process.env,
    NODE_ENV: "development",
  });
  const app = gateway(cfg);
  return {
    plugins: [
      solid(),
      {
        name: "hook-session-gateway",
        configureServer(server) {
          server.middlewares.use((req, res, next) => {
            if (
              req.url?.startsWith("/console/") ||
              req.url?.startsWith("/auth/callback")
            )
              void app.handle(req, res);
            else next();
          });
          if (server.httpServer instanceof Server)
            app.attachWs(server.httpServer);
        },
      },
    ],
    build: { outDir: "dist/client" },
  };
});
