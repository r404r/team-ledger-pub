<script setup lang="ts">
import { emptyComponent, type TermsForm } from './compensationDTO'
defineProps<{ model: TermsForm; prefix: string; disabled?: boolean }>()
</script>
<template>
  <fieldset :disabled="disabled" :aria-label="`${prefix} 完整条款`">
    <legend>完整条款（无币种、周期、税制默认值；不换汇、不合计）</legend>
    <label :for="`${prefix}-currency`">币种（部署批准的三位大写代码）</label><input :id="`${prefix}-currency`" v-model="model.currency" autocomplete="off" />
    <label :for="`${prefix}-scale`">最小单位精度 scale（0..9）</label><input :id="`${prefix}-scale`" v-model="model.scale" inputmode="numeric" autocomplete="off" />
    <label :for="`${prefix}-mode`">明确金额或费率</label><select :id="`${prefix}-mode`" v-model="model.mode"><option value="">请选择</option><option value="amount">最小单位金额</option><option value="rate">精确费率</option></select>
    <label v-if="model.mode === 'amount'" :for="`${prefix}-amount`">金额（规范非负 int64 字符串）</label><input v-if="model.mode === 'amount'" :id="`${prefix}-amount`" v-model="model.amount" inputmode="numeric" autocomplete="off" />
    <label v-if="model.mode === 'rate'" :for="`${prefix}-rate`">费率（规范精确十进制，不自动换算工资）</label><input v-if="model.mode === 'rate'" :id="`${prefix}-rate`" v-model="model.rate" inputmode="decimal" autocomplete="off" />
    <label :for="`${prefix}-unit`">单位口径（部署批准）</label><input :id="`${prefix}-unit`" v-model="model.unit" autocomplete="off" />
    <label :for="`${prefix}-frequency`">支付频次（部署批准）</label><input :id="`${prefix}-frequency`" v-model="model.frequency" autocomplete="off" />
    <label :for="`${prefix}-tax`">税制口径（部署批准）</label><select :id="`${prefix}-tax`" v-model="model.tax"><option value="">请选择</option><option value="gross">gross</option><option value="net">net</option><option value="not_applicable">not_applicable</option></select>
    <fieldset v-for="(component, index) in model.components" :key="index" :aria-label="`${prefix} 组成 ${index + 1}`">
      <legend>组成 {{ index + 1 }}（继承明确币种 / scale，不隐式继承其他口径）</legend>
      <label :for="`${prefix}-component-${index}-code`">组成代码</label><input :id="`${prefix}-component-${index}-code`" v-model="component.code" autocomplete="off" />
      <label :for="`${prefix}-component-${index}-mode`">组成金额或费率</label><select :id="`${prefix}-component-${index}-mode`" v-model="component.mode"><option value="">请选择</option><option value="amount">最小单位金额</option><option value="rate">精确费率</option></select>
      <label v-if="component.mode === 'amount'" :for="`${prefix}-component-${index}-amount`">组成金额</label><input v-if="component.mode === 'amount'" :id="`${prefix}-component-${index}-amount`" v-model="component.amount" inputmode="numeric" autocomplete="off" />
      <label v-if="component.mode === 'rate'" :for="`${prefix}-component-${index}-rate`">组成费率</label><input v-if="component.mode === 'rate'" :id="`${prefix}-component-${index}-rate`" v-model="component.rate" inputmode="decimal" autocomplete="off" />
      <label :for="`${prefix}-component-${index}-unit`">组成单位</label><input :id="`${prefix}-component-${index}-unit`" v-model="component.unit" autocomplete="off" />
      <label :for="`${prefix}-component-${index}-frequency`">组成支付频次</label><input :id="`${prefix}-component-${index}-frequency`" v-model="component.frequency" autocomplete="off" />
      <label :for="`${prefix}-component-${index}-tax`">组成税制口径</label><select :id="`${prefix}-component-${index}-tax`" v-model="component.tax"><option value="">请选择</option><option value="gross">gross</option><option value="net">net</option><option value="not_applicable">not_applicable</option></select>
      <button type="button" @click="model.components.splice(index, 1)">移除组成 {{ index + 1 }}</button>
    </fieldset>
    <button type="button" :disabled="model.components.length >= 20" @click="model.components.push(emptyComponent())">增加组成</button>
  </fieldset>
</template>
