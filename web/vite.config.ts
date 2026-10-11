import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom',
    // Browser storage belongs to jsdom, not Node's process-wide disk backend.
    poolOptions: {
      forks: { execArgv: ['--no-experimental-webstorage'] },
      threads: { execArgv: ['--no-experimental-webstorage'] },
    },
    environmentOptions: {
      jsdom: { url: 'https://team-ledger.example.invalid/' },
    },
    include: ['src/**/*.test.ts'],
  },
})
