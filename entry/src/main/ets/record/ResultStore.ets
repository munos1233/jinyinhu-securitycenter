import { Writer } from './Writer'

export class ResultStore {
  static read(jobId: string): string | null {
    let path = 'center/jobs/' + jobId + '.json'
    let text = Writer.readText(path)
    if (text === null) {
      return null
    }
    try {
      JSON.parse(text)
      return text
    } catch (err) {
      return null
    }
  }
}
