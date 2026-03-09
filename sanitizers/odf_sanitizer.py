from pathlib import Path
from sanitizers.base import Detection, SanitizeResult, Sanitizer, replace_detections_in_text
from detectors.engine import analyze_text
from utils.streaming import check_zip_bomb


class ODFSanitizer(Sanitizer):
    def _iter_text_nodes(self, doc):
        """Yield (text_node, parent_element) pairs from ODF document."""
        def walk(node):
            if hasattr(node, 'childNodes'):
                for child in node.childNodes:
                    if hasattr(child, 'data'):
                        yield child, node
                    else:
                        yield from walk(child)

        yield from walk(doc.text if hasattr(doc, 'text') else doc)

    def detect(
        self,
        custom_terms: tuple[str, ...] = (),
        enabled_entities: frozenset[str] | None = None,
        progress_callback=None,
    ) -> list[Detection]:
        check_zip_bomb(self.path)
        from odf.opendocument import load
        doc = load(str(self.path))
        detections = []
        parts = []
        nodes = []
        offset = 0
        for text_node, _parent in self._iter_text_nodes(doc):
            content = text_node.data
            parts.append(content)
            nodes.append((text_node, offset, offset + len(content)))
            offset += len(content)
        all_text = "".join(parts)

        results = analyze_text(all_text, custom_terms, enabled_entities)
        for r in results:
            detections.append(Detection(
                entity_type=r.entity_type,
                original_value=all_text[r.start:r.end],
                start=r.start,
                end=r.end,
                score=r.score,
                page_or_line="odf",
            ))
        return detections

    def sanitize(self, detections: list[Detection], output_path: Path, session) -> SanitizeResult:
        check_zip_bomb(self.path)
        try:
            from odf.opendocument import load
            doc = load(str(self.path))
            parts = []
            nodes = []
            offset = 0
            for text_node, parent in self._iter_text_nodes(doc):
                content = text_node.data
                parts.append(content)
                nodes.append((text_node, offset, offset + len(content)))
                offset += len(content)
            all_text = "".join(parts)

            if session is not None:
                session.initialize_from_content([all_text])
            all_text = replace_detections_in_text(all_text, detections, session)

            # Put all modified text in the first node and clear the rest.
            # Using original node lengths is incorrect when token lengths differ from
            # original values — text would be lost or misaligned.
            if nodes:
                nodes[0][0].data = all_text
                for text_node, _, _ in nodes[1:]:
                    text_node.data = ""

            output_path.parent.mkdir(parents=True, exist_ok=True)
            doc.save(str(output_path))
            return SanitizeResult(source_path=self.path, output_path=output_path, detections=detections)
        except Exception as e:
            return SanitizeResult(source_path=self.path, error=str(e))
