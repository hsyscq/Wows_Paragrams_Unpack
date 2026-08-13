# Korabli 粒子效果（EffectPrototype）文件格式

> 记录格式逆向来源：`assets.bin`（PrototypeDatabase blob 5）、`korabli64.exe`（Ghidra）、`D:\Korabli64.dmp`（运行内存）。
> 关联实现：`uncode_assets/decoders.py::decode_effect`（尽力解析）。

---

## 1. EffectPrototype 记录（blob 5，magic 0xEB23E0AF，item_size 0x10）

### 1.1 记录布局（16 字节，小端）

```
+0x00  f32  scalar（通常 -1.0 或正数如 9.5，语义未知）
+0x04  u32  count（子节点/条目数）
+0x08  u32  relptr（基准 = blob 起点 → 本记录 OOL 区域起点）
+0x0C  u32  pad（0）
```

### 1.2 指针与 OOL 约定

- **relptr 基准 = blob 起点**（非记录起点）。依据：相邻记录的 relptr 单调递增且 OOL 区域**首尾相接、无间隙**（rec0 `0x9A90` → rec1 `0xAEAF` → rec2 `0xC2CE` → ...）。
- **OOL 区域** = `[relptr, 下一记录 relptr)`。
- OOL 内含**内嵌原始字符串**（非 strings 表，直接内联在 OOL 字节里）与重复的 16B 节点模式：`-1.0f/1.0f + u32 count + u32 偏移 + pad`。

### 1.3 内嵌字符串（实测样本）

```
particles/animated/Smoke_2_8x8.dds
particles/textures/circle_02.tga
particles/animated/SparkLine_12x1.dds
sparks
glow_0
Biggy_fire_2
```

### 1.4 解码输出（decode_effect）

| 字段 | 说明 |
|------|------|
| `scalar` / `count` / `relptr` / `pad` | 记录头部字段 |
| `ool_size` | OOL 区域字节数 |
| `embedded_strings` | OOL 内嵌可打印字符串（粒子资源路径） |
| `candidate_nodes` | 16B 对齐候选节点头（`{offset, value(f32), count, relptr, pad}`，启发式） |
| `ool_hex` | OOL 头部十六进制（前 256B） |

> 节点完整字段语义分派到 `fx` 命名空间各类（见 §2），需逐类逆向。

---

## 2. 粒子系统类型表（fx 命名空间）

粒子效果图由 EffectPrototype 组合下列原型构成（RTTI 类型名来自 exe 数据区）：

### 2.1 Action*Prototype（粒子动作，16 个）

```
ActionAlphaSetterPrototype      ActionBarrierBoxPrototype
ActionBarrierCylinderPrototype  ActionBarrierPlanePrototype
ActionBarrierSpherePrototype    ActionDampferPrototype
ActionEffectSpawnerPrototype    ActionForcePrototype
ActionJitterPrototype           ActionMagnetPrototype
ActionOrbitorPrototype          ActionResizerPrototype
ActionScalerPrototype           ActionStreamPrototype
ActionSystemCreatorPrototype    ActionTintShaderPrototype
ActionTrailSpawnerPrototype
```

### 2.2 Generator（值生成器）

```
ConstantValueGenerator    CumulativeValueGenerator
RampValueGenerator        RandomValueGenerator
ValueGeneratorPrototype
VectorGeneratorPrototype  VectorGeneratorBoxPrototype
VectorGeneratorCylinderPrototype  VectorGeneratorLinePrototype
VectorGeneratorPointPrototype     VectorGeneratorSpherePrototype
VectorGeneratorPrototypeCollection
```

### 2.3 其它 fx Prototype

```
AnimationPrototype    ColorKeyFramePrototype  ComponentPrototype
DecalSourcePrototype  DistancePrototype       EffectPrototype
EffectMetadataPrototype  EffectPresetPrototype  EmitterPrototype
FloatValueKeyFramePrototype  GeneralPrototype  IntensitiesPrototype
IntensityMetadataPrototype  IntensityPrototype  LightSourcePrototype
ParticleActionPrototype  PSPrototype（ParticleSystem）  RendererPrototype
ScalerPrototype  SystemActionPrototype  TintPrototype  TrailPrototype
ValueGeneratorPrototype  VolumePrototype
```

### 2.4 枚举

```
ActionBarrierReaction        ParticleActionType
ParticleCoordinateStyle      ParticleVolumetricsVisibilityMode
ParticlesAnimationType       SystemActionType
ValueGeneratorRampParameterType  ValueGeneratorRampSamplingType
ValueGeneratorType           VectorGeneratorType
```

### 2.5 粒子组装关系（推断）

```
EffectPrototype → EmitterPrototype[] → PSPrototype（粒子系统）
   └─ ParticleActionPrototype[]（Action*：Force/Jitter/Orbitor/Resizer/TintShader/...）
   └─ VectorGeneratorPrototype[]（初始速度/位置）
   └─ ValueGeneratorPrototype[]（Ramp/Constant/Cumulative/Random → 关键帧）
   └─ RendererPrototype / TrailPrototype（粒子轨迹）/ LightSourcePrototype
```

---

## 3. Lesta 加密 pyc 格式（scripts-lst / scripts3.zip）

### 3.1 文件头

```
magic 0x0A0D0D6F（"6F 0D 0D 0A"，Lesta 标志）  flags=0
timestamp + source_size
marshal 数据从偏移 16 开始
```

### 3.2 marshal 格式差异（Lesta 改版 Python 3.7）

- `FLAG_REF`(0x80)：对象类型最高位为 1 时先占位后填充（支持自引用/循环引用）。
- `TYPE_CODE = 0xE3`（`0x63 | FLAG_REF`）。
- `TYPE_REF = 0x72`：索引是 **4 字节 int**（非标准变长 long——关键差异）。
- code 对象多一个 `extra` 字段（位于 `flags` 与 `code` 之间）。
- 无 `posonlyargcount` / 无 `qualname`（3.7 风格，需回退）。
- 字符串以 bytes 存储（`TYPE_STRING`/`TYPE_SHORT_ASCII` 等）。

code 对象字段顺序：
`argcount, kwonlyargcount, nlocals, stacksize, flags, extra(Lesta), code, consts, names, varnames, freevars, cellvars, filename, name, firstlineno, lnotab`

### 3.3 加载器模板（加密层）

每个 pyc 顶层是一个加载器存根：

```
name = "Lesta Studio..|..SPB"   filename = "Lesta"   firstlineno = 148
names: exec, locals, print
consts: [None, "Warnings.nets | Lesta Studio", "an error occurred while loading module",
        <加密数据，如 11937B>]
bytecode（44B）：FF FC FF 0F 7A 09 ...（0xFF/0x7A 为非标准 opcode）
```

- 真实模块代码加密在 `consts[3]`（高熵，非简单 XOR——首字节反推 key 不重复）。
- 运行时由自定义 opcode（`0xFF`/`0x7A`）解密 `consts[3]` → 恢复 code 对象 → `exec(code, globals, locals)`。
- 因此仅凭 `pyc_tools`（`pyc_parser.py`/`pyc_inspect.py`）只能解析加密壳，不能产出可读 Python；完整解密需逆向 exe 内解释器的 0xFF opcode 处理器。

### 3.4 内存中已解密内容（运行 dump 中）

已解密脚本在进程堆区，可直接提取：
- **代码对象 const 池**（方法名/字符串常量）：如 `EffectsUtils`、`getShipHullEffects`、`getWeatherEffectList`、`getAirSupportEffects`、`getMissilesEffects`、`Effect '%s' is not attached` 等。
- **co_filename**（`scripts\EffectsGroupName.pyc`、完整 `...scripts3.zip\scripts\...pyc` 路径）。
- **脚本包路径索引表**（`scripts\pXXXX\...pyc` 全列表）。
