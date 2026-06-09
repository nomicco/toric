import { AdminWebsocket } from "@holochain/client";

const ws = await AdminWebsocket.connect({
  url: new URL("ws://localhost:44121"),
  wsClientOptions: { origin: "http://localhost" },
});

await ws.enableApp({ installed_app_id: "toric" });

try {
  const { port } = await ws.attachAppInterface({ port: 44122, allowed_origins: "*" });
  console.log("App interface attached on port", port);
} catch(e) {
  if (e.message?.includes("already")) {
    console.log("Interface already attached");
  } else {
    throw e;
  }
}

await ws.client.close();