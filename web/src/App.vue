<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import ProfilePage from './ProfilePage.vue'
import GrantPage from './GrantPage.vue'
import IdentityGate from './IdentityGate.vue'
import OrganizationPage from './OrganizationPage.vue'
import InterviewPage from './InterviewPage.vue'
import CompensationPage from './CompensationPage.vue'
import BonusPage from './BonusPage.vue'
import FollowupPage from './FollowupPage.vue'

const pathname = ref(window.location.pathname)
const grantsRoute = computed(() => /^\/security\/grants\/?$/.test(pathname.value))
const organizationRoute = computed(() => /^\/orgs\/[0-9a-f-]+\/(?:tree|employees)\/?$/.test(pathname.value) ||
  /^\/employees\/[0-9a-f-]+\/organization-history\/?$/.test(pathname.value))
const interviewRoute = computed(() => /^\/interviews(?:\/[0-9a-f-]+)?\/?$/.test(pathname.value) ||
  /^\/employees\/[0-9a-f-]+\/interviews\/?$/.test(pathname.value))
const followupRoute = computed(() => /^\/employees\/[0-9a-f-]+\/followup\/?$/.test(pathname.value))
const compensationRoute = computed(() => /^\/employees\/[0-9a-f-]+\/compensation\/?$/.test(pathname.value))
const bonusRoute = computed(() => /^\/employees\/[0-9a-f-]+\/bonuses\/?$/.test(pathname.value))

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
  <IdentityGate v-slot="{ expireSession, orgID }">
    <nav aria-label="主导航">
      <a href="/" @click="navigate($event, '/')">人员资料</a>
      <a href="/security/grants" @click="navigate($event, '/security/grants')">授权</a>
      <a :href="`/orgs/${orgID}/tree`" @click="navigate($event, `/orgs/${orgID}/tree`)">组织树</a>
      <a :href="`/orgs/${orgID}/employees`" @click="navigate($event, `/orgs/${orgID}/employees`)">员工目录</a>
      <a href="/interviews" @click="navigate($event, '/interviews')">面谈</a>
    </nav>
    <GrantPage v-if="grantsRoute" @session-expired="expireSession" />
    <InterviewPage v-else-if="interviewRoute" @session-expired="expireSession" />
    <FollowupPage v-else-if="followupRoute" @session-expired="expireSession" />
    <CompensationPage v-else-if="compensationRoute" @session-expired="expireSession" />
    <BonusPage v-else-if="bonusRoute" @session-expired="expireSession" />
    <OrganizationPage v-else-if="organizationRoute" @session-expired="expireSession" />
    <ProfilePage v-else @session-expired="expireSession" />
  </IdentityGate>
</template>

<style scoped>
nav { max-width: 72rem; margin: 1rem auto; padding: 0 1rem; display: flex; gap: 1.5rem; font-family: system-ui, sans-serif; }
</style>
