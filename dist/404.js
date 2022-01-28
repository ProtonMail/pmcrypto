/*! For license information please see 404.js.LICENSE.txt */
"use strict";(self.webpackChunkpmcrypto=self.webpackChunkpmcrypto||[]).push([[404],{404:(e,t,u)=>{u.r(t),u.d(t,{default:()=>n});var i=u(290);u(638),"undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self&&self;class r{constructor(e){if(void 0===e)throw Error("Invalid BigInteger input");this.value=new i.default(e)}clone(){const e=new r(null);return this.value.copy(e.value),e}iinc(){return this.value.iadd(new i.default(1)),this}inc(){return this.clone().iinc()}idec(){return this.value.isub(new i.default(1)),this}dec(){return this.clone().idec()}iadd(e){return this.value.iadd(e.value),this}add(e){return this.clone().iadd(e)}isub(e){return this.value.isub(e.value),this}sub(e){return this.clone().isub(e)}imul(e){return this.value.imul(e.value),this}mul(e){return this.clone().imul(e)}imod(e){return this.value=this.value.umod(e.value),this}mod(e){return this.clone().imod(e)}modExp(e,t){const u=t.isEven()?i.default.red(t.value):i.default.mont(t.value),r=this.clone();return r.value=r.value.toRed(u).redPow(e.value).fromRed(),r}modInv(e){if(!this.gcd(e).isOne())throw Error("Inverse does not exist");return new r(this.value.invm(e.value))}gcd(e){return new r(this.value.gcd(e.value))}ileftShift(e){return this.value.ishln(e.value.toNumber()),this}leftShift(e){return this.clone().ileftShift(e)}irightShift(e){return this.value.ishrn(e.value.toNumber()),this}rightShift(e){return this.clone().irightShift(e)}equal(e){return this.value.eq(e.value)}lt(e){return this.value.lt(e.value)}lte(e){return this.value.lte(e.value)}gt(e){return this.value.gt(e.value)}gte(e){return this.value.gte(e.value)}isZero(){return this.value.isZero()}isOne(){return this.value.eq(new i.default(1))}isNegative(){return this.value.isNeg()}isEven(){return this.value.isEven()}abs(){const e=this.clone();return e.value=e.value.abs(),e}toString(){return this.value.toString()}toNumber(){return this.value.toNumber()}getBit(e){return this.value.testn(e)?1:0}bitLength(){return this.value.bitLength()}byteLength(){return this.value.byteLength()}toUint8Array(e="be",t){return this.value.toArrayLike(Uint8Array,e,t)}}const n=r}}]);