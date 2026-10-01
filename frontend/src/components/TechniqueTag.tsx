export function TechniqueTag({ id }: { id: string }) {
  return (
    <a
      className="tech-tag tnum"
      href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`}
      target="_blank"
      rel="noreferrer"
      title={`MITRE ATT&CK ${id}`}
    >
      {id}
    </a>
  )
}
