import ReactMarkdown from 'react-markdown';

/** Markdown renderer, split into its own chunk (see dynamic import in the incident page). */
export default function Markdown({ content }: { content: string }) {
  return <ReactMarkdown>{content}</ReactMarkdown>;
}
