from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.function_interface_surface import apply_x86_16_function_interface_surface


def test_function_interface_surface_prepends_header_and_annotates_calls(monkeypatch):
    caller = SimpleNamespace(
        addr=0x1000,
        name="caller",
        info={
            "register_inputs": ("ax", "ds"),
            "register_outputs": ("ax",),
            "return_kind": "word",
        },
    )
    callee = SimpleNamespace(
        addr=0x2000,
        name="callee",
        info={
            "register_inputs": ("bx", "es"),
            "register_outputs": ("ax", "cf"),
            "return_kind": "word",
        },
    )

    function_map = {
        0x1000: caller,
        0x2000: callee,
    }
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: function_map.get(addr),
            )
        )
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, name="caller"),
        render_text=lambda _cfunc: "int caller(void)\n{\n    ax = callee(bx);\n    return ax;\n}\n",
    )

    monkeypatch.setattr(
        "angr_platforms.X86_16.function_interface_surface.collect_neighbor_call_targets",
        lambda _function: [SimpleNamespace(target_addr=0x2000)],
    )

    assert apply_x86_16_function_interface_surface(project, codegen) is True
    rendered = codegen.render_text(codegen.cfunc)

    assert rendered.startswith("// interface caller\n//   in:  ax, ds\n//   out: ax\n//   ret: word\nint caller(void)")
    assert "ax = callee(bx); /* io callee: in=bx, es; out=ax, cf; ret=word */" in rendered


def test_function_interface_surface_formats_low_memory_effects(monkeypatch):
    caller = SimpleNamespace(
        addr=0x1000,
        name="caller",
        info={
            "memory_reads": ("0x40:0x17/1",),
            "memory_writes": ("0x402/2",),
            "return_kind": "void",
        },
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: caller if addr == 0x1000 else None,
            )
        )
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, name="caller"),
        render_text=lambda _cfunc: "void caller(void)\n{\n    return;\n}\n",
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.function_interface_surface.collect_neighbor_call_targets",
        lambda _function: [],
    )

    assert apply_x86_16_function_interface_surface(project, codegen) is True
    rendered = codegen.render_text(codegen.cfunc)

    assert "//   mem-r: bda.keyboard_flags0 (0x40:0x17 -> 0x417)" in rendered
    assert "//   mem-w: bda.com2_port (0x0:0x402 -> 0x402)" in rendered


def test_function_interface_surface_installs_once(monkeypatch):
    caller = SimpleNamespace(addr=0x1000, name="caller", info={})
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: caller if addr == 0x1000 else None,
            )
        )
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, name="caller"),
        render_text=lambda _cfunc: "int caller(void)\n{\n    return 0;\n}\n",
    )

    monkeypatch.setattr(
        "angr_platforms.X86_16.function_interface_surface.collect_neighbor_call_targets",
        lambda _function: [],
    )

    assert apply_x86_16_function_interface_surface(project, codegen) is True
    assert apply_x86_16_function_interface_surface(project, codegen) is False
