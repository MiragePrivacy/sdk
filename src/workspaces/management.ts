import {ApiError} from "../errors";
import {WorkspaceClient,type PolicyResponse} from "./client";
import type {MemberKeys} from "./keys";
import {linkedKeyBranches,linkHash,createIdentityLink,createIdentityRotation,type IdentityLinkState} from "./identity";
import {currentMemberKey} from "./policy";
import {WorkspaceKeyring} from "./personal";

export interface UnlockedIdentity {keys:MemberKeys;client:WorkspaceClient}
export interface IdentityManagementProgress {completed:number;total:number}
/** Keys remain caller-owned. A failed/aborted run can resume from signed policy. */
export async function unlinkOtherIdentity(input:readonly UnlockedIdentity[],progress?:(value:IdentityManagementProgress)=>void):Promise<void> {
  const identities=[...input].sort((a,b)=>b.keys.generation-a.keys.generation);
  let retained:UnlockedIdentity|undefined,state:IdentityLinkState|undefined;
  for(const identity of identities){const links=await identity.client.links();if(links.length){retained=identity;state=links[0];break;}}
  if(!retained||!state)return;
  const target=(link:IdentityLinkState)=>{
    const branches=linkedKeyBranches(link),own=branches.findIndex(branch=>branch.get(retained!.keys.memberKeyId)===retained!.keys.kemPublicKey);
    if(own<0||identities.some(identity=>branches[own].get(identity.keys.memberKeyId)!==identity.keys.kemPublicKey))throw new Error("Management keys must belong to one sign-in branch");
    return branches[1-own];
  };
  let removed=target(state);
  try{await retained.client.deleteLink(state,[...removed.keys()].at(-1)!);return;}
  catch(error){if(!(error instanceof ApiError&&error.statusCode===409))throw error;}
  // Freeze comes first. Refresh afterward to include a generation/enrollment
  // which committed just before the global lock was acquired.
  const refreshed=await retained.client.links();if(!refreshed.length)return;state=refreshed[0];removed=target(state);
  if(!state.unlinking)throw new Error("Identity enrollment was not frozen");
  const workspaces=[...new Set(state.workspaceIds)];let completed=0;progress?.({completed,total:workspaces.length});
  for(const workspace of workspaces){
    for(let attempt=0;attempt<4;attempt++){
      let selected:{identity:UnlockedIdentity;policy:PolicyResponse}|undefined;
      for(const identity of identities){
        try{selected={identity,policy:await identity.client.policy(workspace)};break;}
        catch(error){if(!(error instanceof ApiError&&[401,403,404].includes(error.statusCode)))throw error;}
      }
      // The other identity may have personal workspaces never shared with us.
      // Only the server's final global check decides whether unlink can finish.
      if(!selected)break;
      const {identity}=selected;let policy=selected.policy;
      const ring=new WorkspaceKeyring(workspace,identity.keys);
      try{
        for(;;){
          await ring.load(policy);
          const actor=currentMemberKey(policy.policy,identity.keys.memberKeyId)!;
          const key=actor.member.keys.find(key=>key.removedAtVersion===null&&removed.has(key.memberKeyId));
          if(!key)break;
          const operation=await ring.prepareRemoveKey(key.memberKeyId);if(!operation)break;
          policy=await identity.client.append(operation);
        }
        break;
      }catch(error){if(!(error instanceof ApiError&&[401,409].includes(error.statusCode))||attempt===3)throw error;}
      finally{ring.close();}
    }
    completed++;progress?.({completed,total:workspaces.length});
  }
  await retained.client.deleteLink(state,[...removed.keys()].at(-1)!);
}

/** Finish previously published generation changes before creating a new link. */
export async function completeIdentityRotations(input:readonly UnlockedIdentity[]):Promise<void> {
  const identities=[...input].sort((a,b)=>a.keys.generation-b.keys.generation);
  for(const identity of identities){
    const discovery=await identity.client.discover();
    if(!discovery.rotations.length)continue;
    const pointer=discovery.rotations[0],replacement=identities.find(item=>item.keys.memberKeyId===pointer.newKey);
    if(!replacement)throw new Error("Unlock the latest sign-in generation before continuing");
    for(const workspace of discovery.workspaceIds){
      for(let attempt=0;attempt<4;attempt++){
        let ring:WorkspaceKeyring|undefined;
        try{
          const policy=await identity.client.policy(workspace);
          const actor=currentMemberKey(policy.policy,identity.keys.memberKeyId)!;
          const existing=currentMemberKey(policy.policy,replacement.keys.memberKeyId);
          if(existing){
            if(existing.member.memberId!==actor.member.memberId)throw new Error("Replacement already belongs to another member");
            const next=await replacement.client.policy(workspace);ring=new WorkspaceKeyring(workspace,replacement.keys);await ring.load(next);
            const remove=await ring.prepareRemoveKey(identity.keys.memberKeyId);if(remove)await replacement.client.append(remove);
          }else{
            ring=new WorkspaceKeyring(workspace,identity.keys);await ring.load(policy);
            await identity.client.append(await ring.prepareMemberRotation(replacement.keys,pointer));
          }
          break;
        }catch(error){
          if(error instanceof ApiError&&[401,403,404].includes(error.statusCode))break;
          if(!(error instanceof ApiError&&error.statusCode===409)||attempt===3)throw error;
        }finally{ring?.close();}
      }
    }
  }
}

/** Enroll both sign-ins in the union of their workspaces; personal histories stay distinct. */
export async function linkIdentities(leftInput:readonly UnlockedIdentity[],rightInput:readonly UnlockedIdentity[],progress?:(value:IdentityManagementProgress)=>void):Promise<void> {
  const left=[...leftInput].sort((a,b)=>b.keys.generation-a.keys.generation),right=[...rightInput].sort((a,b)=>b.keys.generation-a.keys.generation);
  if(!left.length||!right.length)throw new Error("Two unlocked sign-ins are required");
  await completeIdentityRotations(left);await completeIdentityRotations(right);
  const a=left[0],b=right[0];
  if((await a.client.discover()).rotations.length||(await b.client.discover()).rotations.length)throw new Error("Unlock the latest sign-in generation before linking");
  const [aLinks,bLinks]=await Promise.all([a.client.links(),b.client.links()]);
  let state=aLinks[0]??bLinks[0];
  if(aLinks[0]&&bLinks[0]&&linkHash(aLinks[0].link)!==linkHash(bLinks[0].link))throw new Error("A sign-in is already linked elsewhere");
  const validate=(value:IdentityLinkState)=>{
    if(value.unlinking)throw new Error("Finish unlinking before linking sign-ins");
    const branches=linkedKeyBranches(value),first=branches.findIndex(branch=>branch.get(a.keys.memberKeyId)===a.keys.kemPublicKey);
    if(first<0||branches[1-first].get(b.keys.memberKeyId)!==b.keys.kemPublicKey)throw new Error("A sign-in is already linked elsewhere");
  };
  if(state)validate(state);
  else {
    try{await a.client.registerLink(createIdentityLink(a.keys,b.keys,Math.floor(Date.now()/1000)),b.client);}
    catch(error){if(!(error instanceof ApiError&&error.statusCode===409))throw error;}
    state=(await a.client.links())[0];if(!state)throw new Error("Identity link registration did not settle");validate(state);
  }
  const workspaces=new Set(state.workspaceIds);
  for(const identity of [a,b])for(const workspace of (await identity.client.discover()).workspaceIds)workspaces.add(workspace);
  let completed=0;progress?.({completed,total:workspaces.size});
  for(const workspace of workspaces){
    for(let attempt=0;attempt<4;attempt++){
      let ring:WorkspaceKeyring|undefined;
      try{
        let selected:{identity:UnlockedIdentity;peer:UnlockedIdentity;policy:PolicyResponse}|undefined;
        for(const [identity,peer] of [[a,b],[b,a]]){
          try{selected={identity,peer,policy:await identity.client.policy(workspace)};break;}
          catch(error){if(!(error instanceof ApiError&&[401,403,404].includes(error.statusCode)))throw error;}
        }
        if(!selected)throw new Error("A workspace is no longer accessible to either sign-in");
        ring=new WorkspaceKeyring(workspace,selected.identity.keys);await ring.load(selected.policy);
        const operation=await ring.prepareLinkedKey(state,selected.peer.keys);
        if(operation)await selected.identity.client.append(operation);
        break;
      }catch(error){if(!(error instanceof ApiError&&error.statusCode===409)||attempt===3)throw error;}
      finally{ring?.close();}
    }
    completed++;progress?.({completed,total:workspaces.size});
  }
}

/** Publish one replacement and revoke every active membership of its older keys. */
export async function replaceIdentity(input:readonly UnlockedIdentity[],replacement:UnlockedIdentity):Promise<void>{
  const previous=[...input].sort((a,b)=>b.keys.generation-a.keys.generation),latest=previous[0];
  if(!latest||replacement.keys.generation!==latest.keys.generation+1)throw new Error("Replacement must be the next sign-in generation");
  await completeIdentityRotations([...previous,replacement]);
  let pointers=(await latest.client.discover()).rotations;
  if(!pointers.length){
    try{await latest.client.registerRotation(createIdentityRotation(latest.keys,replacement.keys,Math.floor(Date.now()/1000)));}
    catch(error){if(!(error instanceof ApiError&&error.statusCode===409))throw error;}
    pointers=(await latest.client.discover()).rotations;
  }
  const pointer=pointers[0];
  if(pointers.length!==1||pointer.newKey!==replacement.keys.memberKeyId||pointer.newKem!==replacement.keys.kemPublicKey||pointer.generation!==replacement.keys.generation)throw new Error("Unlock the published replacement generation before continuing");
  await completeIdentityRotations([...previous,replacement]);
  // Session denial alone is insufficient evidence: a transient authorization
  // failure must not be reported as successful revocation everywhere.
  for(const old of previous)if((await old.client.discover()).workspaceIds.length)throw new Error("Replacement is incomplete in some workspaces; retry to continue");
}
