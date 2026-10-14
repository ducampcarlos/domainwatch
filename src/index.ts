#!/usr/bin/env node
import { VERSION, buildApp, productionDeps } from "./app.js";
import { EXIT, USAGE, UsageError, checkOnce, formatVerdict, parseArgs } from "./cli.js";
import { loadConfig } from "./config.js";

async function main(argv: string[]): Promise<number> {
  let command;
  try {
    command = parseArgs(argv);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    console.error(`${error.message}\n\nRun "domainwatch --help" for usage.`);
    return 64;
  }

  switch (command.name) {
    case "help":
      console.log(USAGE);
      return 0;
    case "version":
      console.log(VERSION);
      return 0;
    case "check": {
      try {
        const verdict = await checkOnce(productionDeps({ allowPrivate: command.allowPrivate }), command);
        console.log(formatVerdict(command, verdict, process.stdout.isTTY === true && !process.env.NO_COLOR));
        return EXIT[verdict.status];
      } catch (error) {
        if (!(error instanceof UsageError)) throw error;
        console.error(error.message);
        return 64;
      }
    }
    case "serve": {
      let config;
      try {
        config = loadConfig();
      } catch (error) {
        console.error(error instanceof Error ? error.message : String(error));
        return 64;
      }
      const app = buildApp(config);
      await new Promise<void>((resolve, reject) => {
        app.server.once("error", reject);
        app.server.listen(config.port, config.host, resolve);
      });
      app.scheduler.start();
      console.log(`domainwatch ${VERSION} listening on http://${config.host}:${config.port} (${app.db.countMonitors()} monitors, data in ${config.dataDir})`);
      if (config.host !== "127.0.0.1" && config.host !== "::1" && config.host !== "localhost") console.log("Note: the API uses a bearer token over plain HTTP; put a TLS-terminating proxy in front of it.");
      if (config.allowPrivate) console.log("Private-address monitoring is ON (DOMAINWATCH_ALLOW_PRIVATE).");
      await new Promise<void>((resolve) => {
        const stop = () => {
          console.log("Shutting down...");
          void app.close().then(resolve);
        };
        process.once("SIGINT", stop);
        process.once("SIGTERM", stop);
      });
      return 0;
    }
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (error: unknown) => {
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exit(1);
  },
);
