<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import ProfilePage from './ProfilePage.vue'
import GrantPage from './GrantPage.vue'
import IdentityGate from './IdentityGate.vue'

const pathname = ref(window.location.pathname)
const grantsRoute = computed(() => /^\/security\/grants\/?$/.test(pathname.value))

function readRoute() {
  pathname.value = window.location.pathname
}
function navigate(event: MouseEvent, path: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
  event.preventDefault()
  window.history.pushState({}, '', path)
  // Both the composition root and the existing profile page consume popstate.
  window.dispatchEvent(new PopStateEvent('popstate'))
}
onMounted(() => window.addEventListener('popstate', readRoute))
onBeforeUnmount(() => window.removeEventListener('popstate', readRoute))
</script>

<template>
  <IdentityGate v-slot="{ expireSession }">
    <nav aria-label="主导航">
      <a href="/" @click="navigate($event, '/')">人员资料</a>
      <a href="/security/grants" @click="navigate($event, '/security/grants')">授权</a>
    </nav>
    <GrantPage v-if="grantsRoute" @session-expired="expireSession" />
    <ProfilePage v-else @session-expired="expireSession" />
  </IdentityGate>
</template>

<style scoped>
nav { max-width: 72rem; margin: 1rem auto; padding: 0 1rem; display: flex; gap: 1.5rem; font-family: system-ui, sans-serif; }
</style>
