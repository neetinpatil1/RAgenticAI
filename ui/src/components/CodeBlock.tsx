interface CodeBlockProps {
  snippet: string;
  language?: string;
}

export function CodeBlock({ snippet }: CodeBlockProps) {
  const lines = snippet.split("\n");

  return (
    <div className="rounded-lg bg-gray-900 border border-gray-700 overflow-x-auto text-xs">
      <table className="w-full border-collapse font-mono">
        <tbody>
          {lines.map((line, i) => {
            const isVulnerable = line.trimStart().startsWith(">>>");
            const displayLine = isVulnerable ? line.replace(/^(\s*)>>>/, "$1   ") : line;
            return (
              <tr
                key={i}
                className={isVulnerable ? "code-vulnerable" : ""}
              >
                <td className="select-none text-gray-600 text-right px-3 py-0.5 w-10 border-r border-gray-800">
                  {i + 1}
                </td>
                <td className="px-3 py-0.5 whitespace-pre text-gray-300">
                  {isVulnerable ? (
                    <span className="text-red-300">{displayLine}</span>
                  ) : (
                    displayLine
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
