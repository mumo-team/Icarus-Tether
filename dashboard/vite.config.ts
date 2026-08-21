import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // strictPort: 포트가 물려 있을 때 조용히 5174로 옮기지 않고 큰 소리로 실패한다.
  // 브리지가 Origin을 localhost:5173으로 잠가둬서(dashboard-bridge.ts ALLOWED_ORIGINS),
  // 포트가 밀리면 웹소켓이 401로 거부되고 화면엔 '대기 중'만 뜬 채 원인이 안 보인다.
  server: { port: 5173, strictPort: true },
});
