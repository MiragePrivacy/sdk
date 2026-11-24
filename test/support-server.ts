import {vi} from "vitest";
import type {Hex} from "viem";
import {SUPPORT_MEMBER_ID,applyPolicyOp,currentMemberKey,type Policy,type PolicyOp} from "../src/workspaces/policy";
import type {RecordRow} from "../src/workspaces/client";
import type {EncryptedRecord,Realm} from "../src/workspaces/records";
import type {SignedIdentityRotation} from "../src/workspaces/identity";
import type {SupportRoot} from "../src/workspaces/support";

interface Stored {ops:PolicyOp[];policy:Policy;records:Map<Hex,RecordRow>;creator:Hex;blocked:boolean;activity:number;createdAt:string}
const reply=(status:number,body?:unknown)=>new Response(body===undefined?null:JSON.stringify(body),{status,headers:{"Content-Type":"application/json"}});
const principal=(hash:Hex)=>`principal.${hash}`;

/** In-memory stand-in for the API's workspace and support routes. */
export function supportServer(apiServer="https://api.example") {
  const realms:Record<Realm,Map<Hex,Stored>>={workspaces:new Map(),support:new Map()};
  const sessions=new Map<string,{realm:Realm;workspace:Hex;key:Hex}>();
  const pointers=new Map<Hex,SignedIdentityRotation>();
  const invites=new Map<Hex,{grant:unknown;ciphertext:unknown}>();
  const requests:{method:string;path:string}[]=[];
  const discoveryRealm=new Map<string,Realm>();
  let root:SupportRoot|null=null,staffWorkspaceId:Hex|null=null,sequence=0,counter=0,staleConfigs=0;
  const failures:{match:(method:string,path:string)=>boolean;status:number}[]=[];
  const chain=(key:Hex)=>{const result:SignedIdentityRotation[]=[];for(let next=pointers.get(key);next;next=pointers.get(next.newKey))result.push(next);return result;};
  const config=(stale:boolean)=>{
    if(!root||!staffWorkspaceId)return {rootKeyId:null,rootKem:null,supportMemberId:SUPPORT_MEMBER_ID,staffWorkspaceId:null,rotations:[],current:null};
    const rotations=chain(root.rootKeyId).slice(0,stale?-1:undefined),tip=rotations.at(-1);
    return {...root,supportMemberId:SUPPORT_MEMBER_ID,staffWorkspaceId,rotations,
      current:tip?{memberKeyId:tip.newKey,kemPublicKey:tip.newKem,generation:tip.generation}:{memberKeyId:root.rootKeyId,kemPublicKey:root.rootKem,generation:0}};
  };
  const now=()=>new Date().toISOString();
  const fetcher=vi.fn(async(input:string|URL,init:RequestInit={}):Promise<Response>=>{
    const url=new URL(String(input)),method=init.method??"GET",headers=init.headers as Record<string,string>|undefined;
    const bearer=headers?.Authorization?.replace("Bearer ","")??"",body=typeof init.body==="string"?JSON.parse(init.body):undefined;
    let path=url.pathname;requests.push({method,path});
    const failure=failures.findIndex(item=>item.match(method,path));
    if(failure!==-1)return reply(failures.splice(failure,1)[0].status,{error:"injected"});
    if(path==="/support/config"){const stale=staleConfigs>0;if(stale)staleConfigs--;return reply(200,config(stale));}
    if(path==="/identity/challenge"||path==="/support/identity/challenge"){discoveryRealm.set(url.searchParams.get("member")!,path.startsWith("/support")?"support":"workspaces");return reply(200,{purpose:"discovery",workspaceId:null,memberKeyId:url.searchParams.get("member"),principalHash:bearer.replace("principal.",""),nonce:`0x${"20".repeat(32)}`,expiresAt:Math.floor(Date.now()/1000)+300});}
    if(path==="/identity/links")return reply(200,[]);
    if(path==="/identity/rotations"&&method==="POST"){
      if(pointers.has(body.oldKey))return reply(409,{error:"rotation exists"});
      pointers.set(body.oldKey,body);return reply(200,body);
    }
    const realm:Realm=path.startsWith("/support/")?"support":"workspaces";
    if(realm==="support")path=path.slice("/support".length);
    const store=realms[realm],parts=path.split("/").filter(Boolean);
    const sessionFor=(workspace:Hex)=>{
      const session=sessions.get(bearer),stored=store.get(workspace);
      return session&&stored&&session.realm===realm&&session.workspace===workspace&&currentMemberKey(stored.policy,session.key)?session:null;
    };
    if(parts[0]==="admin"){
      if(!staffWorkspaceId||!sessionFor(staffWorkspaceId))return reply(403,{error:"staff session required"});
      if(parts.length===2){
        const since=Number(url.searchParams.get("since")??0),limit=Number(url.searchParams.get("limit")??50);
        const rows=[...store].filter(([id,stored])=>id!==staffWorkspaceId&&stored.activity>since).sort((a,b)=>a[1].activity-b[1].activity);
        const page=rows.slice(0,limit),support=(stored:Stored)=>stored.policy.members.find(member=>member.memberId===SUPPORT_MEMBER_ID);
        return reply(200,{workspaces:page.map(([workspaceId,stored])=>{
          const latest=[...stored.records.values()].sort((a,b)=>b.changeSequence-a.changeSequence)[0];
          return {workspaceId,changeSequence:stored.activity,recordCount:stored.records.size,createdAt:stored.createdAt,updatedAt:now(),blocked:stored.blocked,
            awaitingSupport:!!latest&&!support(stored)?.keys.some(key=>key.memberKeyId===latest.record.authorKeyId)};
        }),nextCursor:String(page.at(-1)?.[1].activity??since),hasMore:rows.length>page.length});
      }
      const target=store.get(parts[2] as Hex);if(!target)return reply(404,{error:"unknown workspace"});
      target.blocked=method==="POST";return reply(204);
    }
    if(parts[0]==="invites"){
      const invite=invites.get(parts[1] as Hex),stored=invite&&store.get((invite.grant as {workspaceId:Hex}).workspaceId);
      if(!invite||!stored)return reply(404,{error:"unknown invite"});
      if(method==="GET")return reply(200,{...invite,policy:{policy:stored.policy,ops:stored.ops}});
      stored.policy=applyPolicyOp(stored.policy,body,realm);stored.ops.push(body);return reply(200,stored.policy);
    }
    if(parts[0]!=="workspaces")return reply(404,{error:"unknown route"});
    if(parts.length===1&&method==="GET"){
      const member=url.searchParams.get("member") as Hex;
      if(discoveryRealm.get(member)!==realm)return reply(401,{error:"unknown challenge"});
      return reply(200,{workspaceIds:[...store].filter(([,stored])=>currentMemberKey(stored.policy,member)).map(([id])=>id),rotations:chain(member)});
    }
    if(parts.length===1){
      const op=body as PolicyOp;
      if(realms.workspaces.has(op.workspaceId)||realms.support.has(op.workspaceId))return reply(409,{error:"workspace exists"});
      if(realm==="support"&&[...store].some(([id,stored])=>stored.creator===op.signerKeyId&&id!==staffWorkspaceId))return reply(409,{error:"one support workspace per key"});
      let policy:Policy;try{policy=applyPolicyOp(null,op,realm);}catch(error){return reply(400,{error:String(error)});}
      store.set(op.workspaceId,{ops:[op],policy,records:new Map(),creator:op.signerKeyId,blocked:false,activity:++sequence,createdAt:now()});
      return reply(200,policy);
    }
    const workspace=parts[1] as Hex,stored=store.get(workspace);
    if(!stored)return reply(404,{error:"unknown workspace"});
    if(parts[2]==="challenge"){
      const member=url.searchParams.get("member") as Hex;
      if(!currentMemberKey(stored.policy,member))return reply(403,{error:"not a member"});
      return reply(200,{purpose:"session",workspaceId:workspace,memberKeyId:member,principalHash:bearer.replace("principal.",""),nonce:`0x${"21".repeat(32)}`,expiresAt:Math.floor(Date.now()/1000)+300});
    }
    if(parts[2]==="sessions"){
      const member=currentMemberKey(stored.policy,body.memberKeyId);
      if(!member)return reply(403,{error:"not a member"});
      const token=`${realm==="support"?"mirage_sp_":"mirage_ws_"}${String(++counter).padStart(43,"0")}`;
      sessions.set(token,{realm,workspace,key:body.memberKeyId});
      return reply(200,{token,workspaceId:workspace,memberKeyId:body.memberKeyId,caps:member.member.caps,policyVersion:stored.policy.policyVersion,expiresAt:Math.floor(Date.now()/1000)+3600});
    }
    const session=sessionFor(workspace);
    if(!session)return reply(401,{error:"invalid session"});
    if(parts[2]==="policy"&&parts.length===3)return reply(200,{policy:stored.policy,ops:stored.ops});
    if(parts[2]==="policy"||parts[2]==="support-member"){
      const op=body as PolicyOp,provision=parts[2]==="support-member";
      if(provision&&(realm!=="support"||op.kind!=="add_support_member"))return reply(400,{error:"only add_support_member"});
      if(!provision&&op.kind==="add_support_member")return reply(403,{error:"use the support-member route"});
      if(stored.blocked&&currentMemberKey(stored.policy,session.key)?.member.memberId!==SUPPORT_MEMBER_ID)return reply(403,{error:"blocked"});
      if(op.prevOpHash!==stored.policy.headHash)return reply(409,{error:"stale head"});
      let policy:Policy;try{policy=applyPolicyOp(stored.policy,op,realm);}catch(error){return reply(400,{error:String(error)});}
      if(op.kind==="add_support_member"){
        const current=config(false).current;
        if(!current)return reply(403,{error:"support is not configured"});
        if(op.payload.key.memberKeyId!==current.memberKeyId)return reply(409,{error:"stale support generation"});
      }
      stored.policy=policy;stored.ops.push(op);stored.activity=++sequence;return reply(200,policy);
    }
    if(parts[2]==="invites"&&method==="POST"){
      if(body.policyOp){stored.policy=applyPolicyOp(stored.policy,body.policyOp,realm);stored.ops.push(body.policyOp);}
      invites.set(body.grant.grantId,{grant:body.grant,ciphertext:body.ciphertext});
      return reply(200,{grant:body.grant,ciphertext:body.ciphertext,policy:{policy:stored.policy,ops:stored.ops}});
    }
    if(parts[2]==="invites")return reply(200,[]);
    if(parts[2]==="records"&&parts.length===3){
      const since=Number(url.searchParams.get("since")??0),type=url.searchParams.get("type");
      const rows=[...stored.records.values()].filter(row=>row.changeSequence>since&&(!type||row.record.type===type)).sort((a,b)=>a.changeSequence-b.changeSequence);
      const page=rows.slice(0,100);
      return reply(200,{records:page,nextCursor:String(page.at(-1)?.changeSequence??since),hasMore:rows.length>page.length});
    }
    if(parts[2]==="records"){
      const existing=stored.records.get(parts[3] as Hex);
      if(method==="GET")return existing?reply(200,existing):reply(404,{error:"unknown record"});
      const record=body as EncryptedRecord;
      if(stored.blocked)return reply(403,{error:"blocked"});
      if(Number(headers?.["If-Match"])!==(existing?.record.revision??0)||record.revision!==(existing?.record.revision??0)+1||(record.type==="support_message"&&record.revision>2))return reply(412,{error:"revision conflict"});
      const row:RecordRow={record,changeSequence:++sequence,createdAt:existing?.createdAt??now(),updatedAt:now()};
      stored.records.set(record.recordId,row);stored.activity=sequence;return reply(200,row);
    }
    return reply(404,{error:"unknown route"});
  });
  vi.stubGlobal("fetch",fetcher);
  return {
    apiServer,realms,pointers,requests,principal,
    configure(nextRoot:SupportRoot,staff:Hex){root=nextRoot;staffWorkspaceId=staff;},
    /** The next `count` config responses omit the newest rotation. */
    serveStaleConfig(count=1){staleConfigs=count;},
    /** The next matching request fails with `status`. */
    failOnce(match:(method:string,path:string)=>boolean,status=500){failures.push({match,status});},
    workspace:(id:Hex)=>realms.support.get(id)!,
  };
}
