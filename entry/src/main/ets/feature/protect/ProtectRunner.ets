import type { ProtectFact } from '../../center/CenterTypes'
import type { ProtectContext } from '../../task/Contexts'
import { RunEnd } from '../../task/RunnerRegistry'
import type { ResultHand } from '../../task/RunnerRegistry'

/** Each posture query reports its own result, even when another is unavailable. */
export class ProtectRunner {
  async run(ctx: ProtectContext, hand: ResultHand): Promise<RunEnd> {
    let facts: ProtectFact[] = []
    try {
      facts.push(await ctx.posture.pureMode())
    } catch (err) {
      facts.push(unreadable('pure-mode', '1', '无法读取纯净模式'))
    }
    try {
      facts.push(await ctx.posture.lockdown())
    } catch (err) {
      facts.push(unreadable('lockdown', 'confidentiality', '无法读取锁定状态'))
    }
    try {
      facts.push(await ctx.posture.el5())
    } catch (err) {
      facts.push(unreadable('el5', '在', '无法读取加密服务'))
    }
    hand.save(facts)
    let end = new RunEnd()
    end.itemCount = facts.length
    end.riskCount = facts.filter((fact: ProtectFact): boolean => fact.status === 'risk').length
    return end
  }
}

function unreadable(id: string, expected: string, detail: string): ProtectFact {
  return { id: id, status: 'unsupported', expected: expected, actual: '', detail: detail }
}
