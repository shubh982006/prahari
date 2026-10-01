interface Props {
  id: string
  active?: boolean
  onHover?: (id: string | null) => void
  onSelect?: (id: string) => void
}

export function CitationChip({ id, active, onHover, onSelect }: Props) {
  return (
    <button
      type="button"
      className={`cite tnum ${active ? 'is-active' : ''}`}
      onMouseEnter={() => onHover?.(id)}
      onMouseLeave={() => onHover?.(null)}
      onFocus={() => onHover?.(id)}
      onBlur={() => onHover?.(null)}
      onClick={() => onSelect?.(id)}
      aria-label={`Evidence ${id}: show in attack chain`}
    >
      {id}
    </button>
  )
}
