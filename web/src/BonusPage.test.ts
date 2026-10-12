import { afterEach,describe,expect,it,vi } from 'vitest'
import { flushPromises,mount,type VueWrapper } from '@vue/test-utils'
import BonusPage from './BonusPage.vue'

const ORG='10000000-0000-4000-8000-000000000001',SUBJECT='10000000-0000-4000-8000-000000000002',EMPLOYEE='10000000-0000-4000-8000-000000000003',AWARD='10000000-0000-4000-8000-000000000004'
const session={subject_id:SUBJECT,org_id:ORG,auth_epoch:'1',csrf_token:'csrf',mfa_recent:true,mfa_valid_until:'2099-01-01T00:00:00Z'}
const view={employee_id:EMPLOYEE,bonus_revision:'1',comp_revision:'0',authorization_until:'2099-01-01T00:00:00Z',next_cursor:'',targets:[],awards:[{id:AWARD,employee_id:EMPLOYEE,state:'draft',revision:'1',bonus_revision:'1',author_subject_id:SUBJECT,recorded_at:'2026-10-12T00:00:00Z',target_id:null,corrects_award_id:null,approval_id:null,award:{period_start:'2026-01-01',period_end:'2026-12-31',category:'performance',reason:'SYNTHETIC',amount:{currency:'USD',scale:2,amount_minor:'9007199254740993'}},decision_reason:''}],payments:[],balances:[],anomalies:[],extensions:[],permissions:[{capability:'compensation.read',category:'financial'},{capability:'bonus.propose',category:'financial'}]}
const pages:VueWrapper[]=[]
afterEach(()=>{for(const page of pages)page.unmount();pages.length=0;vi.unstubAllGlobals()})
async function settle(){await flushPromises();await Promise.resolve()}

describe('P-BONUS-01',()=>{
  it('renders exact minor units and submits one explicit transition before reloading',async()=>{
    history.replaceState({},'',`/employees/${EMPLOYEE}/bonuses`)
    const calls:{url:string;init:RequestInit}[]=[]
    vi.stubGlobal('fetch',vi.fn(async(input:RequestInfo|URL,init:RequestInit={})=>{const url=String(input);calls.push({url,init});if(url.endsWith('/session'))return new Response(JSON.stringify(session),{status:200,headers:{'Content-Type':'application/json'}});if(url.includes('/bonuses?'))return new Response(JSON.stringify(view),{status:200,headers:{'Content-Type':'application/json'}});if(url.endsWith(`/bonus-awards/${AWARD}/transitions`))return new Response(JSON.stringify({id:AWARD,revision:'2',bonus_revision:'2',comp_revision:'0',state:'submitted'}),{status:200,headers:{'Content-Type':'application/json'}});return new Response('',{status:404})}))
    const page=mount(BonusPage,{attachTo:document.body});pages.push(page);await settle()
    expect(page.text()).toContain('9007199254740993 USD/2')
    await page.get('.confirm input').setValue(true)
    await page.findAll('button').find(button=>button.text()==='提交')!.trigger('click');await settle()
    const mutation=calls.find(call=>call.url.endsWith(`/bonus-awards/${AWARD}/transitions`))!
    expect(mutation.init.method).toBe('POST')
    expect(JSON.parse(String(mutation.init.body))).toEqual({action:'submit',revision:'1',bonus_revision:'1',decision_reason:''})
    expect(new Headers(mutation.init.headers).get('X-Access-Purpose')).toBe('compensation_management')
    expect(new Headers(mutation.init.headers).get('X-CSRF-Token')).toBe('csrf')
    expect(calls.filter(call=>call.url.endsWith(`/bonus-awards/${AWARD}/transitions`))).toHaveLength(1)
    expect(calls.filter(call=>call.url.includes('/bonuses?'))).toHaveLength(2)
  })
})
