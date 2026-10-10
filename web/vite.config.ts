import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom',
    environmentOptions: {
      jsdom: { url: 'https://team-ledger.example.invalid/' },
    },
    include: ['src/**/*.test.ts'],
  },
})
