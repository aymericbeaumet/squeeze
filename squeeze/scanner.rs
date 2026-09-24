use crate::classify::{self, BLOCK, Backend, CAT_NONE, CATEGORY, Lanes, Rules};
use crate::{Anchor, ByteSet, Finder, Memo, RunCache, RunHint, RunRule, Runs};
use std::fmt;
use std::mem::MaybeUninit;
use std::ops::Range;

const CL_DIGIT: u16 = 1 << 0;
const CL_HEX_ALPHA: u16 = 1 << 1;
const CL_ALPHA_OTHER: u16 = 1 << 2;
const CL_AT: u16 = 1 << 3;
const CL_DOLLAR: u16 = 1 << 4;
const CL_HASH: u16 = 1 << 5;
const CL_OPEN_BRACE: u16 = 1 << 6;
const CL_OPEN_BRACKET: u16 = 1 << 7;
const CL_COLON: u16 = 1 << 8;
const CL_DOT: u16 = 1 << 9;
const CL_SLASH: u16 = 1 << 10;
const CL_TILDE: u16 = 1 << 11;
const CL_PLUS: u16 = 1 << 12;
const CL_OPEN_PAREN: u16 = 1 << 13;
const CL_DASH: u16 = 1 << 14;

const CL_ALL_USED: u16 = (1 << 15) - 1;
const CL_HEX: u16 = CL_DIGIT | CL_HEX_ALPHA;

const fn build_byte_class_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0u16;
    while i < 256 {
        let b = i as u8;
        let mut c = 0u16;
        if b >= b'0' && b <= b'9' {
            c |= CL_DIGIT;
        }
        if (b >= b'a' && b <= b'f') || (b >= b'A' && b <= b'F') {
            c |= CL_HEX_ALPHA;
        }
        if (b >= b'g' && b <= b'z') || (b >= b'G' && b <= b'Z') {
            c |= CL_ALPHA_OTHER;
        }
        if b == b'@' {
            c |= CL_AT;
        }
        if b == b'$' {
            c |= CL_DOLLAR;
        }
        if b == b'#' {
            c |= CL_HASH;
        }
        if b == b'{' {
            c |= CL_OPEN_BRACE;
        }
        if b == b'[' {
            c |= CL_OPEN_BRACKET;
        }
        if b == b':' {
            c |= CL_COLON;
        }
        if b == b'.' {
            c |= CL_DOT;
        }
        if b == b'/' {
            c |= CL_SLASH;
        }
        if b == b'~' {
            c |= CL_TILDE;
        }
        if b == b'+' {
            c |= CL_PLUS;
        }
        if b == b'(' {
            c |= CL_OPEN_PAREN;
        }
        if b == b'-' {
            c |= CL_DASH;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
}

static BYTE_CLASSES: [u16; 256] = build_byte_class_table();

/// Coarse byte classes used to index the context gate tables. Bytes that
/// finders single out in their boundary rules get their own class so the
/// gates stay exact for them; everything else is grouped.
const CTX_CLASSES: usize = 18;
/// Class used when there is no byte (start or end of the line).
const CTX_NONE: usize = CTX_CLASSES - 1;

const fn ctx_class(b: u8) -> usize {
    match b {
        b'0'..=b'9' => 0,
        b'a'..=b'f' | b'A'..=b'F' => 1,
        b'g' | b'G' => 2,
        b's' | b'S' => 3,
        b'y' | b'Y' => 4,
        b'h'..=b'z' | b'H'..=b'Z' => 5,
        b'.' => 6,
        b':' => 7,
        b'-' => 8,
        b'_' => 9,
        b'/' => 10,
        b'@' => 11,
        b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C => 12,
        0x80..=0xBF => 13,
        0xC0..=0xFF => 14,
        b'(' | b'[' | b'{' | b'<' | b'"' | b'\'' | b'`' | b'=' | b'>' => 15,
        _ => 16,
    }
}

const fn build_ctx_class_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = ctx_class(i as u8) as u8;
        i += 1;
    }
    table
}

static CTX_CLASS: [u8; 256] = build_ctx_class_table();

/// Vector categories covering a context class (see `classify`).
fn ctx_class_category(class: usize) -> u8 {
    match class {
        0 => classify::CAT_DIGIT,
        1 => classify::CAT_HEX_ALPHA,
        2 => classify::CAT_ALPHA_GO,
        3 | 4 => classify::CAT_ALPHA_PZ,
        5 => classify::CAT_OTHER_ALPHA,
        6 => classify::CAT_DOT,
        7 => classify::CAT_COLON,
        13 | 14 => classify::CAT_HIGH,
        _ => classify::CAT_OTHER,
    }
}

#[inline]
fn prescan(input: &[u8]) -> u16 {
    let mut classes = 0u16;
    let (chunks, remainder) = input.as_chunks::<8>();
    for chunk in chunks {
        classes |= BYTE_CLASSES[chunk[0] as usize]
            | BYTE_CLASSES[chunk[1] as usize]
            | BYTE_CLASSES[chunk[2] as usize]
            | BYTE_CLASSES[chunk[3] as usize]
            | BYTE_CLASSES[chunk[4] as usize]
            | BYTE_CLASSES[chunk[5] as usize]
            | BYTE_CLASSES[chunk[6] as usize]
            | BYTE_CLASSES[chunk[7] as usize];
        if classes == CL_ALL_USED {
            return classes;
        }
    }
    for &b in remainder {
        classes |= BYTE_CLASSES[b as usize];
    }
    classes
}

fn required_classes(id: &str) -> &'static [(u16, bool)] {
    match id {
        "cidr" => &[(CL_DIGIT, true), (CL_SLASH, true)],
        "codetag" => &[(CL_COLON, true)],
        "color" => &[(CL_HASH | CL_ALPHA_OTHER | CL_HEX_ALPHA, false)],
        "datetime" => &[(CL_DIGIT, true)],
        "domain" => &[(CL_DOT, true), (CL_ALPHA_OTHER | CL_HEX_ALPHA, false)],
        "email" => &[(CL_AT, true)],
        "emoji" => &[],
        "env" => &[(CL_DOLLAR, true)],
        "handle" => &[(CL_AT, true)],
        "hash" => &[(CL_HEX, false)],
        "ip" => &[(CL_DIGIT | CL_HEX_ALPHA | CL_COLON | CL_OPEN_BRACKET, false)],
        "json" => &[(CL_OPEN_BRACE | CL_OPEN_BRACKET, false)],
        "jwt" => &[(CL_HEX_ALPHA, false)],
        "mac" => &[(CL_HEX, false), (CL_COLON | CL_DASH | CL_DOT, false)],
        "mirror" => &[],
        "modeline" => &[(CL_COLON, true)],
        "path" => &[(CL_SLASH | CL_DOT | CL_TILDE, false)],
        "phone" => &[(CL_DIGIT | CL_PLUS | CL_OPEN_PAREN, false)],
        "semver" => &[(CL_DIGIT, true), (CL_DOT, true)],
        "uri" => &[(CL_COLON, true)],
        "uuid" => &[(CL_HEX, false), (CL_DASH, true)],
        _ => &[],
    }
}

#[inline]
fn can_skip_with_mask(cl: u16, required: &[(u16, bool)]) -> bool {
    for &(mask, all_required) in required {
        if all_required {
            if cl & mask != mask {
                return true;
            }
        } else if (cl & mask) == 0 {
            return true;
        }
    }
    false
}

const MAX_FINDERS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScannerError {
    TooManyFinders { len: usize, max: usize },
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScannerError::TooManyFinders { len, max } => {
                write!(f, "too many finders: got {}, max is {}", len, max)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub finder_index: usize,
    pub range: Range<usize>,
}

/// Per-finder operation counters, see [`ScanStats`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FinderStats {
    /// Lines on which the finder ran (was not disabled by the prescan).
    pub lines_run: u64,
    /// Calls to [`Finder::find`] (scan mode).
    pub find_calls: u64,
    /// Calls to [`Finder::try_at`] (dispatch mode).
    pub try_at_calls: u64,
    /// Calls to [`Finder::try_trigger_at`] (trigger mode).
    pub try_trigger_calls: u64,
    /// Calls of any kind that returned `Some`.
    pub hits: u64,
    /// Matches kept after the per-finder overlap check.
    pub matches: u64,
}

impl FinderStats {
    /// Total finder invocations of any mode.
    pub fn calls(&self) -> u64 {
        self.find_calls + self.try_at_calls + self.try_trigger_calls
    }

    fn add(&mut self, other: &FinderStats) {
        self.lines_run += other.lines_run;
        self.find_calls += other.find_calls;
        self.try_at_calls += other.try_at_calls;
        self.try_trigger_calls += other.try_trigger_calls;
        self.hits += other.hits;
        self.matches += other.matches;
    }
}

/// Operation counters collected by [`Scanner::scan_line_stats`].
///
/// The counters describe how much work the scanner and its finders did, so
/// that performance can be reasoned about independently of wall-clock time:
/// a finder invocation is the unit of work the scanner dispatches, and the
/// ratio of invocations to hits shows how well candidate filtering works.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Lines scanned (including empty lines).
    pub lines: u64,
    /// Bytes scanned.
    pub bytes: u64,
    /// Lines on which the prescan disabled every finder.
    pub lines_skipped: u64,
    /// Finder×line pairs disabled by the prescan.
    pub finder_lines_skipped: u64,
    /// Positions visited by the dispatch and trigger loops (one per byte and
    /// per loop that ran).
    pub positions: u64,
    /// Positions the vector stage passed on to the exact gates
    /// ([`Strategy::Vector`] only).
    pub coarse_positions: u64,
    /// Positions where at least one candidate finder was invoked.
    pub candidate_positions: u64,
    /// Finder invocations avoided by run rules.
    pub run_gated: u64,
    /// Coarse positions the exact gates rejected, by the byte at the
    /// position (diagnostics for the vector stage's precision).
    pub coarse_rejected: Vec<u64>,
    /// Matches returned to the caller.
    pub matches: u64,
    /// Lines whose matches had to be sorted.
    pub sorts: u64,
    /// One entry per finder, in scanner order.
    pub finders: Vec<FinderStats>,
}

impl ScanStats {
    /// Creates counters sized for `scanner`.
    pub fn for_scanner(scanner: &Scanner) -> Self {
        ScanStats {
            finders: vec![FinderStats::default(); scanner.finders.len()],
            ..Default::default()
        }
    }

    /// Adds `other` into `self`; both must come from scanners with the same
    /// finder list.
    pub fn merge(&mut self, other: &ScanStats) {
        self.lines += other.lines;
        self.bytes += other.bytes;
        self.lines_skipped += other.lines_skipped;
        self.finder_lines_skipped += other.finder_lines_skipped;
        self.positions += other.positions;
        self.coarse_positions += other.coarse_positions;
        self.candidate_positions += other.candidate_positions;
        self.run_gated += other.run_gated;
        if self.coarse_rejected.len() < other.coarse_rejected.len() {
            self.coarse_rejected.resize(other.coarse_rejected.len(), 0);
        }
        for (i, n) in other.coarse_rejected.iter().enumerate() {
            self.coarse_rejected[i] += n;
        }
        self.matches += other.matches;
        self.sorts += other.sorts;
        if self.finders.len() < other.finders.len() {
            self.finders
                .resize(other.finders.len(), FinderStats::default());
        }
        for (a, b) in self.finders.iter_mut().zip(&other.finders) {
            a.add(b);
        }
    }

    /// Total finder invocations of any mode.
    pub fn calls(&self) -> u64 {
        self.finders.iter().map(FinderStats::calls).sum()
    }

    /// Total finder invocations that returned `Some`.
    pub fn hits(&self) -> u64 {
        self.finders.iter().map(|f| f.hits).sum()
    }
}

/// Receives scanner events. `()` ignores them at zero cost; [`ScanStats`]
/// counts them.
trait Probe {
    #[inline(always)]
    fn line(&mut self, _bytes: usize) {}
    #[inline(always)]
    fn line_skipped(&mut self) {}
    #[inline(always)]
    fn finders_skipped(&mut self, _count: u32) {}
    #[inline(always)]
    fn finder_run(&mut self, _finder: usize) {}
    #[inline(always)]
    fn positions(&mut self, _count: usize) {}
    #[inline(always)]
    fn coarse_position(&mut self) {}
    #[inline(always)]
    fn candidate_position(&mut self) {}
    #[inline(always)]
    fn run_gated(&mut self) {}
    #[inline(always)]
    fn run_gated_n(&mut self, _n: u32) {}
    #[inline(always)]
    fn coarse_rejected(&mut self, _cur: u8) {}
    #[inline(always)]
    fn find_call(&mut self, _finder: usize, _hit: bool) {}
    #[inline(always)]
    fn try_at_call(&mut self, _finder: usize, _hit: bool) {}
    #[inline(always)]
    fn try_trigger_call(&mut self, _finder: usize, _hit: bool) {}
    #[inline(always)]
    fn matched(&mut self, _finder: usize) {}
    #[inline(always)]
    fn sorted(&mut self) {}
}

impl Probe for () {}

impl Probe for ScanStats {
    fn line(&mut self, bytes: usize) {
        self.lines += 1;
        self.bytes += bytes as u64;
    }
    fn line_skipped(&mut self) {
        self.lines_skipped += 1;
    }
    fn finders_skipped(&mut self, count: u32) {
        self.finder_lines_skipped += u64::from(count);
    }
    fn finder_run(&mut self, finder: usize) {
        self.finders[finder].lines_run += 1;
    }
    fn positions(&mut self, count: usize) {
        self.positions += count as u64;
    }
    fn coarse_position(&mut self) {
        self.coarse_positions += 1;
    }
    fn candidate_position(&mut self) {
        self.candidate_positions += 1;
    }
    fn run_gated(&mut self) {
        self.run_gated += 1;
    }
    fn run_gated_n(&mut self, n: u32) {
        self.run_gated += u64::from(n);
    }
    fn coarse_rejected(&mut self, cur: u8) {
        if self.coarse_rejected.len() < 256 {
            self.coarse_rejected.resize(256, 0);
        }
        self.coarse_rejected[cur as usize] += 1;
    }
    fn find_call(&mut self, finder: usize, hit: bool) {
        let f = &mut self.finders[finder];
        f.find_calls += 1;
        f.hits += u64::from(hit);
    }
    fn try_at_call(&mut self, finder: usize, hit: bool) {
        let f = &mut self.finders[finder];
        f.try_at_calls += 1;
        f.hits += u64::from(hit);
    }
    fn try_trigger_call(&mut self, finder: usize, hit: bool) {
        let f = &mut self.finders[finder];
        f.try_trigger_calls += 1;
        f.hits += u64::from(hit);
    }
    fn matched(&mut self, finder: usize) {
        self.finders[finder].matches += 1;
        self.matches += 1;
    }
    fn sorted(&mut self) {
        self.sorts += 1;
    }
}

/// How the scanner walks a line. Strategies produce identical matches; they
/// exist so that alternatives can be measured against each other in the
/// same process (see the `scanner` bench).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Strategy {
    /// Byte-by-byte dispatch on the current byte only, dispatch and trigger
    /// finders in separate passes. The original implementation.
    Legacy,
    /// Single pass with context gates: a finder is only invoked when the
    /// previous and next bytes allow a match to start.
    Gated,
    /// Context gates evaluated sixteen bytes at a time with SIMD (or with
    /// `memchr` when the finders start at three bytes or fewer), then the
    /// exact gates on the surviving positions (default).
    Vector,
}

impl Strategy {
    /// All strategies, in evaluation order.
    pub const ALL: &[Strategy] = &[Strategy::Legacy, Strategy::Gated, Strategy::Vector];

    /// Short identifier, e.g. for command-line selection.
    pub fn name(self) -> &'static str {
        match self {
            Strategy::Legacy => "legacy",
            Strategy::Gated => "gated",
            Strategy::Vector => "vector",
        }
    }

    /// Parses [`name`](Strategy::name).
    pub fn parse(name: &str) -> Option<Strategy> {
        Strategy::ALL.iter().copied().find(|s| s.name() == name)
    }
}

/// Per-line state of the dispatch/trigger pass: where each finder's last
/// match ended (matches stay disjoint per finder), each finder's memo, and
/// the run cache. Only the slots of the scanner's finders are initialised:
/// zeroing all `MAX_FINDERS` slots cost more than scanning a short line.
struct LineState {
    finder_pos: [MaybeUninit<usize>; MAX_FINDERS],
    memos: [MaybeUninit<Memo>; MAX_FINDERS],
    /// Anchor plan: positions below this were already tried for the finder.
    tried: [MaybeUninit<usize>; MAX_FINDERS],
    runs: RunCache,
    /// Number of initialised slots.
    len: usize,
}

impl LineState {
    #[inline(always)]
    fn new(len: usize) -> LineState {
        let mut state = LineState {
            finder_pos: [MaybeUninit::uninit(); MAX_FINDERS],
            memos: [MaybeUninit::uninit(); MAX_FINDERS],
            tried: [MaybeUninit::uninit(); MAX_FINDERS],
            runs: RunCache::default(),
            len,
        };
        for i in 0..len {
            state.finder_pos[i].write(0);
            state.memos[i].write(Memo::default());
            state.tried[i].write(0);
        }
        state
    }

    #[inline(always)]
    fn tried(&self, i: usize) -> usize {
        debug_assert!(i < self.len);
        // SAFETY: as in `pos`.
        unsafe { self.tried[i].assume_init() }
    }

    #[inline(always)]
    fn set_tried(&mut self, i: usize, pos: usize) {
        debug_assert!(i < self.len);
        self.tried[i].write(pos);
    }

    #[inline(always)]
    fn pos(&self, i: usize) -> usize {
        debug_assert!(i < self.len);
        // SAFETY: `i` is a finder index, and `new` initialised every slot
        // below `len`, the scanner's finder count.
        unsafe { self.finder_pos[i].assume_init() }
    }

    #[inline(always)]
    fn set_pos(&mut self, i: usize, pos: usize) {
        debug_assert!(i < self.len);
        self.finder_pos[i].write(pos);
    }

    #[inline(always)]
    fn memo(&mut self, i: usize) -> &mut Memo {
        debug_assert!(i < self.len);
        // SAFETY: as in `pos`.
        unsafe { self.memos[i].assume_init_mut() }
    }
}

/// Receives candidate positions from a pass's search.
trait Sink {
    fn candidate(&mut self, scanner: &Scanner, pass: &Pass, pos: usize, hint: Option<&RunHint<'_>>);
    fn stopped(&self) -> bool {
        false
    }
}

/// Per-line scanning: candidates are probed in place.
struct LineSink<'a, P: Probe> {
    input: &'a [u8],
    active_ctx: u32,
    state: LineState,
    matches: &'a mut Vec<Match>,
    probe: &'a mut P,
}

impl<P: Probe> Sink for LineSink<'_, P> {
    #[inline(always)]
    fn candidate(
        &mut self,
        scanner: &Scanner,
        pass: &Pass,
        pos: usize,
        hint: Option<&RunHint<'_>>,
    ) {
        self.probe.coarse_position();
        scanner.probe_position(
            pass,
            self.input,
            pos,
            self.active_ctx,
            &mut self.state,
            self.matches,
            self.probe,
            hint,
        );
    }
}

/// Where a whole-buffer walk sends the matches of a line.
trait LineOutput {
    /// Receives one line's matches, relative to `start`, in candidate
    /// order; returns whether the walk must stop.
    fn line(&mut self, start: usize, end: usize, matches: &mut Vec<Match>) -> bool;
}

/// Emits each line as soon as the walk leaves it.
struct Stream<'a, F: FnMut(usize, usize, &[Match]) -> bool>(&'a mut F);

impl<F: FnMut(usize, usize, &[Match]) -> bool> LineOutput for Stream<'_, F> {
    #[inline(always)]
    fn line(&mut self, start: usize, end: usize, matches: &mut Vec<Match>) -> bool {
        sort_matches(matches);
        (self.0)(start, end, matches)
    }
}

/// Keeps every match with absolute positions, for merging with other passes.
struct Collect<'a>(&'a mut Vec<Match>);

impl LineOutput for Collect<'_> {
    #[inline(always)]
    fn line(&mut self, start: usize, _end: usize, matches: &mut Vec<Match>) -> bool {
        for m in matches.drain(..) {
            self.0.push(Match {
                finder_index: m.finder_index,
                range: m.range.start + start..m.range.end + start,
            });
        }
        false
    }
}

/// Whole-buffer walk of a pass whose finders are bound to lines: the line
/// around each candidate is resolved lazily and its matches go to `out`
/// once the walk leaves it.
struct BufferSink<'a, O: LineOutput> {
    data: &'a [u8],
    line_start: usize,
    /// End of the current line without its terminator and trailing `\r`s.
    line_end: usize,
    /// Start of the next line (past the terminator).
    line_next: usize,
    active_ctx: u32,
    state: LineState,
    matches: Vec<Match>,
    out: O,
    stopped: bool,
}

impl<'a, O: LineOutput> BufferSink<'a, O> {
    fn new(data: &'a [u8], scanner: &Scanner, out: O) -> Self {
        BufferSink {
            data,
            line_start: 0,
            line_end: 0,
            line_next: 0,
            active_ctx: 0,
            state: LineState::new(scanner.finders.len()),
            matches: Vec::new(),
            out,
            stopped: false,
        }
    }

    #[inline(always)]
    fn flush(&mut self) {
        if self.matches.is_empty() || self.stopped {
            return;
        }
        self.stopped = self
            .out
            .line(self.line_start, self.line_end, &mut self.matches);
        self.matches.clear();
    }

    /// Makes the line holding `pos` current.
    #[inline(always)]
    fn enter_line(&mut self, scanner: &Scanner, pass: &Pass, pos: usize) {
        let data = self.data;
        self.line_start = memchr::memrchr(b'\n', &data[..pos]).map_or(0, |nl| nl + 1);
        let nl = memchr::memchr(b'\n', &data[pos..]).map_or(data.len(), |i| pos + i);
        self.line_next = (nl + 1).min(data.len());
        let mut end = nl;
        while end > self.line_start && data[end - 1] == b'\r' {
            end -= 1;
        }
        self.line_end = end;
        self.state = LineState::new(scanner.finders.len());
        let line = &data[self.line_start..self.line_end];
        self.active_ctx = scanner.buffer_active(pass, line);
    }
}

impl<O: LineOutput> Sink for BufferSink<'_, O> {
    #[inline(always)]
    fn candidate(
        &mut self,
        scanner: &Scanner,
        pass: &Pass,
        pos: usize,
        hint: Option<&RunHint<'_>>,
    ) {
        if pos >= self.line_next {
            self.flush();
            if self.stopped {
                return;
            }
            self.enter_line(scanner, pass, pos);
        }
        if pos >= self.line_end || self.active_ctx == 0 {
            return;
        }
        let line = &self.data[self.line_start..self.line_end];
        scanner.probe_position(
            pass,
            line,
            pos - self.line_start,
            self.active_ctx,
            &mut self.state,
            &mut self.matches,
            &mut (),
            hint,
        );
    }

    #[inline(always)]
    fn stopped(&self) -> bool {
        self.stopped
    }
}

/// Whole-buffer walk of a pass whose finders are line-agnostic: candidates
/// are probed with absolute positions and no line is resolved until the
/// matches are grouped for emission.
struct WholeSink<'a> {
    data: &'a [u8],
    state: LineState,
    matches: &'a mut Vec<Match>,
}

impl Sink for WholeSink<'_> {
    #[inline(always)]
    fn candidate(
        &mut self,
        scanner: &Scanner,
        pass: &Pass,
        pos: usize,
        hint: Option<&RunHint<'_>>,
    ) {
        let active_ctx = scanner.dispatch_mask | scanner.trigger_mask;
        scanner.probe_position(
            pass,
            self.data,
            pos,
            active_ctx,
            &mut self.state,
            self.matches,
            &mut (),
            hint,
        );
    }
}

/// Orders matches as `scan_line` reports them: by start, then finder.
#[inline]
fn sort_matches(matches: &mut [Match]) {
    let sorted = matches
        .windows(2)
        .all(|w| (w[0].range.start, w[0].finder_index) <= (w[1].range.start, w[1].finder_index));
    if !sorted {
        // Lists are nearly sorted (a trigger match may start before the
        // previous one); the stable sort exploits the existing runs.
        matches.sort_by(|a, b| {
            a.range
                .start
                .cmp(&b.range.start)
                .then(a.finder_index.cmp(&b.finder_index))
        });
    }
}

/// Merges per-pass match lists, each sorted, into `scan_line` order.
fn merge_matches(mut lists: Vec<Vec<Match>>) -> Vec<Match> {
    lists.retain(|list| !list.is_empty());
    if lists.len() <= 1 {
        return lists.pop().unwrap_or_default();
    }
    let total = lists.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(total);
    let mut heads = vec![0usize; lists.len()];
    loop {
        let mut best: Option<usize> = None;
        for (k, list) in lists.iter().enumerate() {
            if heads[k] >= list.len() {
                continue;
            }
            let m = &list[heads[k]];
            let better = match best {
                None => true,
                Some(b) => {
                    let head = &lists[b][heads[b]];
                    (m.range.start, m.finder_index) < (head.range.start, head.finder_index)
                }
            };
            if better {
                best = Some(k);
            }
        }
        let Some(b) = best else { break };
        out.push(lists[b][heads[b]].clone());
        heads[b] += 1;
    }
    out
}

/// Emits absolute matches, sorted in `scan_line` order, grouped per line
/// with positions relative to the line. Returns whether `emit` stopped.
fn emit_grouped(
    data: &[u8],
    matches: Vec<Match>,
    emit: &mut impl FnMut(usize, usize, &[Match]) -> bool,
) -> bool {
    let mut line_start = 0;
    let mut line_end = 0;
    let mut line_next = 0;
    let mut group: Vec<Match> = Vec::new();
    for m in matches {
        if m.range.start >= line_next || group.is_empty() {
            if !group.is_empty() && emit(line_start, line_end, &group) {
                return true;
            }
            group.clear();
            line_start = memchr::memrchr(b'\n', &data[..m.range.start]).map_or(0, |nl| nl + 1);
            let nl = memchr::memchr(b'\n', &data[m.range.start..])
                .map_or(data.len(), |i| m.range.start + i);
            line_next = (nl + 1).min(data.len());
            line_end = nl;
            while line_end > line_start && data[line_end - 1] == b'\r' {
                line_end -= 1;
            }
        }
        group.push(Match {
            finder_index: m.finder_index,
            range: m.range.start - line_start..m.range.end - line_start,
        });
    }
    if !group.is_empty() && emit(line_start, line_end, &group) {
        return true;
    }
    false
}

/// How a pass finds its candidate positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Search {
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    Blocks,
}

/// One search over the input serving a subset of the finders: `memchr` for
/// up to three bytes (trigger bytes, start bytes or anchor bytes) or the
/// block classifier. Passes have disjoint finder sets.
struct Pass {
    search: Search,
    /// Finders served by this pass.
    finders: u32,
    /// Dispatch finders of this pass reached by walking back from an anchor
    /// byte rather than probed at their start bytes.
    anchored: u32,
    /// Every finder of the pass is line-agnostic, so a buffer can be probed
    /// with absolute positions and lines resolved only around matches.
    whole: bool,
    /// Coarse rules of a `Search::Blocks` pass.
    rules: Option<Rules>,
    /// Every dispatch finder of a `Search::Blocks` pass that can start at a
    /// hex digit needs a hex run of at least this many bytes (0 when one
    /// needs less): the block stage drops shorter runs before any per-lane
    /// work.
    min_hex_run: usize,
}

impl Pass {
    /// The search, for diagnostics: `blocks`, `start bytes(:@)` or
    /// `anchors(-)`.
    fn describe(&self) -> String {
        let show = |list: &[u8]| -> String {
            list.iter()
                .map(|&b| {
                    if b.is_ascii_graphic() {
                        (b as char).to_string()
                    } else {
                        format!("\\x{b:02x}")
                    }
                })
                .collect()
        };
        let what = if self.anchored != 0 {
            "anchors"
        } else {
            "start bytes"
        };
        match self.search {
            Search::One(a) => format!("{what}({})", show(&[a])),
            Search::Two(a, b) => format!("{what}({})", show(&[a, b])),
            Search::Three(a, b, c) => format!("{what}({})", show(&[a, b, c])),
            Search::Blocks => "blocks".to_string(),
        }
    }
}

/// Most `memchr` passes a scanner runs; the finders that do not fit go to
/// the block pass.
const MAX_MEMCHR_PASSES: usize = 3;

/// Longest word run measured for [`RunClass::Word`](crate::RunClass::Word)
/// rules; longer runs report as capped.
const WORD_CAP: usize = 16;

pub struct Scanner {
    finders: Vec<Box<dyn Finder>>,
    strategy: Strategy,
    backend: classify::Kind,
    /// The searches run over each line or buffer, in order.
    passes: Vec<Pass>,
    anchors: Vec<Option<Anchor>>,
    /// Each finder's start bytes (`could_start_at`).
    starts: Vec<ByteSet>,
    /// Start bytes per dispatch finder (`Strategy::Legacy`).
    dispatch: [u32; 256],
    /// Trigger bytes per trigger finder (`Strategy::Legacy`).
    trigger: [u32; 256],
    /// Candidates by (class of previous byte, current byte); row `CTX_NONE`
    /// is the start of the line. Covers dispatch and trigger finders.
    gate_prev: Box<[[u32; 256]; CTX_CLASSES]>,
    /// Candidates by (current byte, class of next byte); column `CTX_NONE`
    /// is the end of the line.
    gate_next: Box<[[u32; CTX_CLASSES]; 256]>,
    dispatch_mask: u32,
    trigger_mask: u32,
    /// Trigger finders with a tabulated context gate.
    context_mask: u32,
    /// Per finder, for each class of the next byte, a bitset over the two
    /// previous bytes (`prev2 << 8 | prev1`) that may hold a trigger.
    contexts: Vec<Option<Box<[[u64; 1024]; CTX_CLASSES]>>>,
    scan_mask: u32,
    /// Finders with digit or hex run rules.
    run_mask: u32,
    run_rules: Vec<Vec<RunRule>>,
    /// Finders with a digit or hex rule applicable at a start byte.
    rule_cur: Box<[u32; 256]>,
    /// Finders with a digit-class (resp. hex-class) rule accepting the byte
    /// after the run; index 256 stands for the end of the input. A finder
    /// absent from both entries for a candidate's runs cannot accept it,
    /// so the rules are only evaluated for the others.
    after_digit: Box<[u32; 257]>,
    after_hex: Box<[u32; 257]>,
    /// Finders with a digit-class (resp. hex-class) rule accepting a run
    /// of the indexed length (up to `RUN_CAP`).
    len_digit: Box<[u32; 130]>,
    len_hex: Box<[u32; 130]>,
    /// Finders with digit-class (resp. hex-class) rules: a capped run may
    /// satisfy any of them.
    digit_ruled: u32,
    hex_ruled: u32,
    /// Longest run any rule needs to distinguish, plus one.
    run_cap: usize,
    /// Finders with a [`RunClass::Word`] rule: the word run is measured
    /// only for their candidates.
    word_mask: u32,
    /// Longest word run any rule needs to distinguish, plus one.
    word_cap: usize,
    skip_requirements: Vec<&'static [(u16, bool)]>,
}

impl Scanner {
    pub fn new(finders: Vec<Box<dyn Finder>>) -> Self {
        Self::try_new(finders).expect("too many finders")
    }

    pub fn try_new(finders: Vec<Box<dyn Finder>>) -> Result<Self, ScannerError> {
        if finders.len() > MAX_FINDERS {
            return Err(ScannerError::TooManyFinders {
                len: finders.len(),
                max: MAX_FINDERS,
            });
        }

        let mut dispatch = [0u32; 256];
        let mut trigger = [0u32; 256];
        let mut dispatch_mask = 0u32;
        let mut trigger_mask = 0u32;
        let mut scan_mask = 0u32;

        let skip_requirements: Vec<&'static [(u16, bool)]> =
            finders.iter().map(|f| required_classes(f.id())).collect();
        let run_rules: Vec<Vec<RunRule>> = finders
            .iter()
            .map(|f| {
                if f.dispatchable() || f.triggerable() {
                    f.run_rules()
                } else {
                    Vec::new()
                }
            })
            .collect();
        // A finder's rules are either all on the word run or all on the
        // digit/hex runs, so each kind is measured only when a candidate
        // finder needs it.
        for (i, rules) in run_rules.iter().enumerate() {
            let words = rules
                .iter()
                .filter(|r| r.class == crate::RunClass::Word)
                .count();
            assert!(
                words == 0 || words == rules.len(),
                "finder {} mixes word rules with digit or hex rules",
                finders[i].id()
            );
        }
        let run_mask = run_rules
            .iter()
            .enumerate()
            .filter(|(_, rules)| rules.iter().any(|r| r.class != crate::RunClass::Word))
            .fold(0u32, |mask, (i, _)| mask | (1u32 << i));
        let mut rule_cur = Box::new([0u32; 256]);
        let mut after_digit = Box::new([0u32; 257]);
        let mut after_hex = Box::new([0u32; 257]);
        let mut len_digit = Box::new([0u32; 130]);
        let mut len_hex = Box::new([0u32; 130]);
        let mut digit_ruled = 0u32;
        let mut hex_ruled = 0u32;
        for (i, rules) in run_rules.iter().enumerate() {
            let bit = 1u32 << i;
            for rule in rules {
                let (after, lens, ruled) = match rule.class {
                    crate::RunClass::Digit => (&mut after_digit, &mut len_digit, &mut digit_ruled),
                    crate::RunClass::Hex => (&mut after_hex, &mut len_hex, &mut hex_ruled),
                    crate::RunClass::Word => continue,
                };
                *ruled |= bit;
                for len in rule.min..=rule.max.min(crate::RUN_CAP) {
                    if rule.lengths == 0 || len >= 64 || rule.lengths & (1u64 << len) != 0 {
                        lens[len as usize] |= bit;
                    }
                }
                for b in 0..=255u8 {
                    if rule.cur.contains(b) {
                        rule_cur[b as usize] |= bit;
                    }
                    if rule.after.contains(b) {
                        after[b as usize] |= bit;
                    }
                }
                if rule.after_end {
                    after[256] |= bit;
                }
            }
        }
        // A run longer than every rule's `max` is rejected whatever follows
        // it, so measuring stops one byte past the longest `max`.
        let run_cap = run_rules
            .iter()
            .flatten()
            .filter(|rule| rule.class != crate::RunClass::Word)
            .map(|rule| rule.max as usize + 1)
            .max()
            .unwrap_or(1)
            .min(crate::RUN_CAP as usize);
        let word_mask = run_rules
            .iter()
            .enumerate()
            .filter(|(_, rules)| rules.iter().any(|r| r.class == crate::RunClass::Word))
            .fold(0u32, |mask, (i, _)| mask | (1u32 << i));
        // A word run is measured up to 16 bytes: enough to check the length
        // and the following byte for every mnemonic-sized rule, while a
        // longer run reports as capped and is accepted whatever the rule's
        // maximum (a rule's minimum never exceeds the cap).
        let word_cap = run_rules
            .iter()
            .flatten()
            .filter(|rule| rule.class == crate::RunClass::Word)
            .map(|rule| (rule.max as usize + 1).min(WORD_CAP).max(rule.min as usize))
            .max()
            .unwrap_or(1);

        let mut gate_prev = Box::new([[0u32; 256]; CTX_CLASSES]);
        let mut gate_next = Box::new([[0u32; CTX_CLASSES]; 256]);

        for (i, finder) in finders.iter().enumerate() {
            let bit = 1u32 << i;
            if finder.dispatchable() {
                dispatch_mask |= bit;
                for cur in 0..=255u8 {
                    if !finder.could_start_at(cur) {
                        continue;
                    }
                    dispatch[cur as usize] |= bit;
                    // A class is allowed as soon as one of its bytes is: the
                    // gate only skips contexts every byte of the class rules
                    // out, so it can never lose a match.
                    gate_prev[CTX_NONE][cur as usize] |= bit;
                    gate_next[cur as usize][CTX_NONE] |= bit;
                    for other in 0..=255u8 {
                        if finder.could_start_after(other, cur) {
                            gate_prev[ctx_class(other)][cur as usize] |= bit;
                        }
                        if finder.could_continue_with(cur, other) {
                            gate_next[cur as usize][ctx_class(other)] |= bit;
                        }
                    }
                }
            } else if finder.triggerable() {
                trigger_mask |= bit;
                for cur in 0..=255u8 {
                    if !finder.could_trigger_at(cur) {
                        continue;
                    }
                    trigger[cur as usize] |= bit;
                    gate_prev[CTX_NONE][cur as usize] |= bit;
                    gate_next[cur as usize][CTX_NONE] |= bit;
                    for other in 0..=255u8 {
                        if finder.could_start_after(other, cur) {
                            gate_prev[ctx_class(other)][cur as usize] |= bit;
                        }
                        if finder.could_continue_with(cur, other) {
                            gate_next[cur as usize][ctx_class(other)] |= bit;
                        }
                    }
                }
            } else {
                scan_mask |= bit;
            }
        }

        let mut context_mask = 0u32;
        let contexts: Vec<Option<Box<[[u64; 1024]; CTX_CLASSES]>>> = finders
            .iter()
            .enumerate()
            .map(|(i, f)| {
                if !f.triggerable() || !f.has_trigger_context() {
                    return None;
                }
                context_mask |= 1u32 << i;
                let mut table = Box::new([[0u64; 1024]; CTX_CLASSES]);
                // A class admits a pair when any byte of the class does; the
                // end of the input is class CTX_NONE.
                let mut nexts: Vec<Vec<Option<u8>>> = vec![Vec::new(); CTX_CLASSES];
                for b in 0..=255u8 {
                    nexts[ctx_class(b)].push(Some(b));
                }
                nexts[CTX_NONE].push(None);
                for (class, bytes) in nexts.iter().enumerate() {
                    for prev2 in 0..=255u8 {
                        for prev1 in 0..=255u8 {
                            if bytes
                                .iter()
                                .any(|&next| f.trigger_context(prev2, prev1, next))
                            {
                                let index = usize::from(prev2) << 8 | usize::from(prev1);
                                table[class][index >> 6] |= 1 << (index & 63);
                            }
                        }
                    }
                }
                Some(table)
            })
            .collect();
        let anchors: Vec<Option<Anchor>> = finders
            .iter()
            .map(|f| if f.dispatchable() { f.anchor() } else { None })
            .collect();
        for (i, anchor) in anchors.iter().enumerate() {
            // An exact offset relies on the walk stopping at anchor bytes:
            // a position before a probed anchor can then never start a
            // match whose first anchor lies beyond it.
            if let Some(anchor) = anchor
                && anchor.back.is_some()
            {
                assert!(
                    (0..=255u8).all(|b| !(anchor.bytes.contains(b) && anchor.walk.contains(b))),
                    "finder {} anchors on a walk byte with an exact offset",
                    finders[i].id()
                );
            }
        }
        let starts: Vec<ByteSet> = finders
            .iter()
            .map(|f| ByteSet::from_fn(|b| f.dispatchable() && f.could_start_at(b)))
            .collect();
        let ctx_mask = dispatch_mask | trigger_mask;

        // Coarse rules of a block pass: for each finder and start byte, the
        // previous/next byte classes its gates accept, mapped to the vector
        // categories. Categories are coarser than classes and unions only
        // widen, so the block stage always yields a superset of the exact
        // gates.
        let build_rules = |mask: u32| -> Rules {
            let mut items = Vec::new();
            for i in 0..finders.len() {
                let bit = 1u32 << i;
                if bit & mask == 0 {
                    continue;
                }
                for b in 0..=255u8 {
                    if gate_prev[CTX_NONE][b as usize] & bit == 0 {
                        continue;
                    }
                    let mut prev = 0u8;
                    let mut next = 0u8;
                    for class in 0..CTX_NONE {
                        if gate_prev[class][b as usize] & bit != 0 {
                            prev |= ctx_class_category(class);
                        }
                        if gate_next[b as usize][class] & bit != 0 {
                            next |= ctx_class_category(class);
                        }
                    }
                    items.push((b, prev, next));
                }
            }
            Rules::build(items)
        };
        // Shortest hex run any hex-starting dispatch finder of `mask` can
        // match: only meaningful when each such finder has hex-class rules
        // covering all its hex start bytes, so that a shorter run rules
        // every finder out. 0 when the filter cannot apply.
        let min_hex_run = |mask: u32| -> usize {
            let mut min_hex_run = usize::MAX;
            for (i, finder) in finders.iter().enumerate() {
                if mask & (1u32 << i) == 0 || !finder.dispatchable() {
                    continue;
                }
                let hex_starts: Vec<u8> = (0..=255u8)
                    .filter(|&b| b.is_ascii_hexdigit() && finder.could_start_at(b))
                    .collect();
                if hex_starts.is_empty() {
                    continue;
                }
                let mut finder_min = usize::MAX;
                for &b in &hex_starts {
                    let mut byte_min = usize::MAX;
                    let mut covered = false;
                    for rule in &run_rules[i] {
                        if !rule.cur.contains(b) {
                            continue;
                        }
                        covered = true;
                        match rule.class {
                            crate::RunClass::Hex => byte_min = byte_min.min(rule.min as usize),
                            // A digit or word rule accepts runs the hex run
                            // does not bound.
                            crate::RunClass::Digit | crate::RunClass::Word => byte_min = 1,
                        }
                    }
                    if !covered {
                        byte_min = 1;
                    }
                    finder_min = finder_min.min(byte_min);
                }
                min_hex_run = min_hex_run.min(finder_min);
            }
            if min_hex_run == usize::MAX || min_hex_run < 2 {
                0
            } else {
                min_hex_run
            }
        };

        // Passes. A finder is searched with `memchr` when a few bytes locate
        // every match: its trigger bytes, its start bytes when they number
        // three or fewer, or its anchor bytes. The rest needs the block
        // classifier, which tests extra start bytes for free, so when a
        // block pass runs anyway the `memchr` finders join it unless they
        // would weaken its hex-run filter. `memchr` finders sharing bytes
        // are grouped three bytes per pass, at most MAX_MEMCHR_PASSES
        // passes; the overflow goes to the block pass.
        let bytes_of =
            |set: &dyn Fn(u8) -> bool| -> Vec<u8> { (0..=255u8).filter(|&b| set(b)).collect() };
        let few = |bytes: &[u8]| (1..=3).contains(&bytes.len());
        let search_bytes = |i: usize| -> Option<(Vec<u8>, bool)> {
            let finder = &finders[i];
            let bit = 1u32 << i;
            if trigger_mask & bit != 0 {
                let bytes = bytes_of(&|b| finder.could_trigger_at(b));
                return few(&bytes).then_some((bytes, false));
            }
            if dispatch_mask & bit == 0 {
                return None;
            }
            let bytes = bytes_of(&|b| starts[i].contains(b));
            if few(&bytes) {
                return Some((bytes, false));
            }
            let anchor = anchors[i]?;
            let bytes = bytes_of(&|b| anchor.bytes.contains(b));
            few(&bytes).then_some((bytes, true))
        };
        let mut cheap: Vec<(usize, Vec<u8>, bool)> = Vec::new();
        let mut block_mask = 0u32;
        for i in 0..finders.len() {
            let bit = 1u32 << i;
            if ctx_mask & bit == 0 {
                continue;
            }
            match search_bytes(i) {
                Some((bytes, anchored)) => cheap.push((i, bytes, anchored)),
                None => block_mask |= bit,
            }
        }
        if block_mask != 0 {
            let base = min_hex_run(block_mask);
            let mut joined = block_mask;
            cheap.retain(|&(i, _, _)| {
                let bit = 1u32 << i;
                let weakens = base >= 2 && min_hex_run(joined | bit) < 2;
                if !weakens {
                    joined |= bit;
                }
                weakens
            });
            block_mask = joined;
        }
        cheap.sort_by_key(|(_, bytes, _)| bytes.len());
        let mut groups: Vec<(Vec<u8>, u32, u32)> = Vec::new();
        for (i, bytes, anchored) in cheap {
            let bit = 1u32 << i;
            let anchored_bit = if anchored { bit } else { 0 };
            let fits = groups.iter_mut().find(|group| {
                let extra = bytes.iter().filter(|b| !group.0.contains(b)).count();
                group.0.len() + extra <= 3
            });
            if let Some(group) = fits {
                for &b in &bytes {
                    if !group.0.contains(&b) {
                        group.0.push(b);
                    }
                }
                group.1 |= bit;
                group.2 |= anchored_bit;
            } else if groups.len() < MAX_MEMCHR_PASSES {
                groups.push((bytes, bit, anchored_bit));
            } else {
                block_mask |= bit;
            }
        }
        let whole_for = |mask: u32| {
            (0..finders.len())
                .filter(|&i| mask & (1u32 << i) != 0)
                .all(|i| finders[i].line_agnostic())
        };
        let mut passes = Vec::new();
        for (mut bytes, mask, anchored) in groups {
            bytes.sort_unstable();
            let search = match bytes.as_slice() {
                [a] => Search::One(*a),
                [a, b] => Search::Two(*a, *b),
                [a, b, c] => Search::Three(*a, *b, *c),
                _ => unreachable!("a memchr pass searches at most three bytes"),
            };
            passes.push(Pass {
                search,
                finders: mask,
                anchored,
                whole: whole_for(mask),
                rules: None,
                min_hex_run: 0,
            });
        }
        if block_mask != 0 {
            passes.push(Pass {
                search: Search::Blocks,
                finders: block_mask,
                anchored: 0,
                whole: whole_for(block_mask),
                rules: Some(build_rules(block_mask)),
                min_hex_run: min_hex_run(block_mask),
            });
        }

        Ok(Scanner {
            finders,
            strategy: Strategy::Vector,
            backend: classify::detect(),
            passes,
            anchors,
            starts,
            dispatch,
            trigger,
            gate_prev,
            gate_next,
            dispatch_mask,
            trigger_mask,
            context_mask,
            contexts,
            scan_mask,
            run_mask,
            run_rules,
            rule_cur,
            after_digit,
            after_hex,
            len_digit,
            len_hex,
            digit_ruled,
            hex_ruled,
            run_cap,
            word_mask,
            word_cap,
            skip_requirements,
        })
    }

    pub fn finders(&self) -> &[Box<dyn Finder>] {
        &self.finders
    }

    /// The line-walking strategy in use.
    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    /// Selects the line-walking strategy; results do not depend on it.
    pub fn set_strategy(&mut self, strategy: Strategy) {
        self.strategy = strategy;
    }

    /// Name of the block classifier used by [`Strategy::Vector`]
    /// (`"neon"`, `"ssse3"` or `"scalar"`), for diagnostics.
    pub fn backend(&self) -> &'static str {
        self.backend.name()
    }

    /// How [`Strategy::Vector`] searches candidates, for diagnostics: the
    /// passes in order, such as `anchors(-)`, `start bytes(:@)` or
    /// `blocks`, joined with ` + `.
    pub fn plan(&self) -> String {
        if self.passes.is_empty() {
            return "none".to_string();
        }
        self.passes
            .iter()
            .map(Pass::describe)
            .collect::<Vec<_>>()
            .join(" + ")
    }

    /// Whether every pass searches with `memchr`, so the prescan has
    /// nothing left to skip.
    #[inline]
    fn all_memchr(&self) -> bool {
        !self.passes.is_empty() && self.passes.iter().all(|p| p.search != Search::Blocks)
    }

    /// Forces the portable block classifier (for tests and benchmarks).
    #[doc(hidden)]
    pub fn use_scalar_backend(&mut self) {
        self.backend = classify::Kind::Scalar;
    }

    #[inline]
    fn compute_active(&self, line_classes: u16) -> u32 {
        let mut active = 0u32;
        for (i, req) in self.skip_requirements.iter().enumerate() {
            if !can_skip_with_mask(line_classes, req) {
                active |= 1u32 << i;
            }
        }
        active
    }

    pub fn scan_line(&self, line: &str) -> Vec<Match> {
        let mut matches = Vec::new();
        self.scan_line_into(line, &mut matches);
        matches
    }

    /// Start of the first line at or after `from` (itself a line start) in
    /// `text` that may contain a match, or `None` when no later line can.
    ///
    /// When the finders start at three bytes or fewer, those bytes are
    /// searched with `memchr` across the whole buffer, so lines that cannot
    /// match are never visited individually; otherwise every line is a
    /// candidate and `from` is returned. Lines end at `\n`.
    pub fn skip_to_candidate_line(&self, text: &[u8], from: usize) -> Option<usize> {
        let from = from.min(text.len());
        // Only a lone memchr pass can prove that a line holds nothing.
        let search = match self.passes.as_slice() {
            [pass] => pass.search,
            _ => return Some(from),
        };
        let hay = &text[from..];
        let hit = match search {
            Search::One(a) => memchr::memchr(a, hay),
            Search::Two(a, b) => memchr::memchr2(a, b, hay),
            Search::Three(a, b, c) => memchr::memchr3(a, b, c, hay),
            Search::Blocks => return Some(from),
        }?;
        let hit = from + hit;
        Some(
            memchr::memrchr(b'\n', &text[from..hit])
                .map(|nl| from + nl + 1)
                .unwrap_or(from),
        )
    }

    pub fn scan_line_into(&self, line: &str, matches: &mut Vec<Match>) {
        self.scan_line_probe(line, matches, &mut ());
    }

    /// Like [`scan_line_into`](Self::scan_line_into), additionally counting
    /// the work performed into `stats`.
    pub fn scan_line_stats(&self, line: &str, matches: &mut Vec<Match>, stats: &mut ScanStats) {
        if stats.finders.len() < self.finders.len() {
            stats
                .finders
                .resize(self.finders.len(), FinderStats::default());
        }
        self.scan_line_probe(line, matches, stats);
    }

    /// Active finders of `pass` for a line reached from the buffer walk:
    /// the prescan pays off for a block pass with several finders; a
    /// `memchr` pass or a single gated finder skips it.
    #[inline]
    fn buffer_active(&self, pass: &Pass, line: &[u8]) -> u32 {
        let ctx = pass.finders;
        let single_gated = self.finders.len() == 1 && ctx != 0;
        if single_gated || pass.search != Search::Blocks || line.is_empty() {
            return ctx;
        }
        self.compute_active(prescan(line)) & ctx
    }

    /// Prescan and per-finder activation shared by every entry point.
    /// Returns the active finder mask, or `None` when nothing can match.
    #[inline]
    fn activate<P: Probe>(&self, input: &[u8], probe: &mut P) -> Option<u32> {
        probe.line(input.len());
        if input.is_empty() {
            probe.line_skipped();
            return None;
        }
        let all = if self.finders.is_empty() {
            0
        } else {
            u32::MAX >> (32 - self.finders.len())
        };
        // A scanner of `memchr` passes walks the line for a few bytes,
        // which already skips everything the prescan could disable,
        // and a single gated finder is filtered at least as well by its own
        // gates and run rules; the prescan would only add a pass over every
        // byte.
        let single_gated = self.finders.len() == 1 && (self.dispatch_mask | self.trigger_mask) != 0;
        if single_gated || (self.all_memchr() && self.strategy == Strategy::Vector) {
            if all == 0 {
                probe.line_skipped();
                return None;
            }
            let mut bits = all;
            while bits != 0 {
                probe.finder_run(bits.trailing_zeros() as usize);
                bits &= bits - 1;
            }
            return Some(all);
        }
        let line_classes = prescan(input);
        let active = self.compute_active(line_classes);
        probe.finders_skipped((all & !active).count_ones());
        if active == 0 {
            probe.line_skipped();
            return None;
        }
        let mut bits = active;
        while bits != 0 {
            probe.finder_run(bits.trailing_zeros() as usize);
            bits &= bits - 1;
        }
        Some(active)
    }

    fn scan_line_probe<P: Probe>(&self, line: &str, matches: &mut Vec<Match>, probe: &mut P) {
        matches.clear();

        let input = line.as_bytes();
        let Some(active) = self.activate(input, probe) else {
            return;
        };

        let active_scan = active & self.scan_mask;
        if active_scan != 0 {
            let mut bits = active_scan;
            while bits != 0 {
                let i = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let finder = &self.finders[i];
                let mut idx = 0;
                while idx < line.len() {
                    let found = finder.find(&line[idx..]);
                    probe.find_call(i, found.is_some());
                    if let Some(range) = found {
                        probe.matched(i);
                        matches.push(Match {
                            finder_index: i,
                            range: (idx + range.start)..(idx + range.end),
                        });
                        idx += range.end;
                    } else {
                        break;
                    }
                }
            }
        }

        match self.strategy {
            Strategy::Legacy => self.walk_legacy(input, active, matches, probe),
            Strategy::Gated => self.walk_gated(input, active, matches, probe),
            Strategy::Vector => self.walk_vector(input, active, matches, probe),
        }

        // Scan-mode matches come first in position order, then the merged
        // dispatch/trigger pass in candidate order; trigger matches may start
        // before their trigger byte, so check before paying for a sort.
        let sorted = matches.windows(2).all(|w| {
            (w[0].range.start, w[0].finder_index) <= (w[1].range.start, w[1].finder_index)
        });
        if !sorted {
            probe.sorted();
            sort_matches(matches);
        }
    }

    /// `Strategy::Legacy`: the original two-pass byte loop.
    fn walk_legacy<P: Probe>(
        &self,
        input: &[u8],
        active: u32,
        matches: &mut Vec<Match>,
        probe: &mut P,
    ) {
        let active_dispatch = active & self.dispatch_mask;
        if active_dispatch != 0 {
            let mut finder_pos = [0usize; MAX_FINDERS];
            probe.positions(input.len());

            for pos in 0..input.len() {
                let mut candidates = self.dispatch[input[pos] as usize] & active_dispatch;
                if candidates == 0 {
                    continue;
                }
                probe.candidate_position();
                while candidates != 0 {
                    let i = candidates.trailing_zeros() as usize;
                    candidates &= candidates - 1;

                    if pos < finder_pos[i] {
                        continue;
                    }
                    let found = self.finders[i].try_at(input, pos);
                    probe.try_at_call(i, found.is_some());
                    if let Some(range) = found {
                        if range.start < finder_pos[i] {
                            continue;
                        }
                        probe.matched(i);
                        matches.push(Match {
                            finder_index: i,
                            range: range.clone(),
                        });
                        finder_pos[i] = range.end;
                    }
                }
            }
        }

        let active_trigger = active & self.trigger_mask;
        if active_trigger != 0 {
            let mut finder_pos = [0usize; MAX_FINDERS];
            probe.positions(input.len());

            for pos in 0..input.len() {
                let mut candidates = self.trigger[input[pos] as usize] & active_trigger;
                if candidates == 0 {
                    continue;
                }
                probe.candidate_position();
                while candidates != 0 {
                    let i = candidates.trailing_zeros() as usize;
                    candidates &= candidates - 1;

                    if pos < finder_pos[i] {
                        continue;
                    }
                    let found = self.finders[i].try_trigger_at(input, pos);
                    probe.try_trigger_call(i, found.is_some());
                    if let Some(range) = found {
                        if range.start < finder_pos[i] {
                            continue;
                        }
                        finder_pos[i] = range.end;
                        probe.matched(i);
                        matches.push(Match {
                            finder_index: i,
                            range,
                        });
                    }
                }
            }
        }
    }

    /// Runs every finder of `pass` the exact gates allow at `pos`, keeping
    /// matches disjoint per finder through `finder_pos`.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn probe_position<P: Probe>(
        &self,
        pass: &Pass,
        input: &[u8],
        pos: usize,
        active_ctx: u32,
        state: &mut LineState,
        matches: &mut Vec<Match>,
        probe: &mut P,
        hint: Option<&RunHint<'_>>,
    ) {
        let active = active_ctx & pass.finders;
        if pass.anchored != 0 {
            self.probe_anchor(input, pos, active & pass.anchored, state, matches, probe);
        }
        let plain = active & !pass.anchored;
        if plain == 0 {
            return;
        }
        let cur = input[pos];
        let prev_class = if pos > 0 {
            CTX_CLASS[input[pos - 1] as usize] as usize
        } else {
            CTX_NONE
        };
        let mut candidates = self.gate_prev[prev_class][cur as usize] & plain;
        if candidates == 0 {
            probe.coarse_rejected(cur);
            return;
        }
        let next_class = if pos + 1 < input.len() {
            CTX_CLASS[input[pos + 1] as usize] as usize
        } else {
            CTX_NONE
        };
        candidates &= self.gate_next[cur as usize][next_class];
        if candidates == 0 {
            probe.coarse_rejected(cur);
            return;
        }
        if candidates & self.context_mask != 0 {
            // Trigger finders with a context table: the two previous bytes
            // and the class of the next one decide before any call.
            let prev1 = if pos > 0 { input[pos - 1] } else { b' ' };
            let prev2 = if pos > 1 { input[pos - 2] } else { b' ' };
            let index = usize::from(prev2) << 8 | usize::from(prev1);
            let mut bits = candidates & self.context_mask;
            while bits != 0 {
                let i = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let table = self.contexts[i]
                    .as_ref()
                    .expect("a context finder has a table");
                if table[next_class][index >> 6] & (1 << (index & 63)) == 0 {
                    candidates &= !(1u32 << i);
                }
            }
            if candidates == 0 {
                probe.coarse_rejected(cur);
                return;
            }
        }
        probe.candidate_position();
        self.invoke(input, pos, candidates, state, matches, probe, hint);
    }

    /// Anchored dispatch finders in `mask`: `pos` may hold one of their
    /// anchor bytes. Each walks back over its `walk` bytes to where a match
    /// could start and tries the dispatch positions in order, exactly as
    /// the dispatch walk would have, without ever retrying a position
    /// (`tried`) so a run with many anchors stays linear.
    #[inline]
    fn probe_anchor<P: Probe>(
        &self,
        input: &[u8],
        pos: usize,
        mask: u32,
        state: &mut LineState,
        matches: &mut Vec<Match>,
        probe: &mut P,
    ) {
        let cur = input[pos];
        let mut bits = mask;
        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            // By reference: the anchor with its check is over a hundred
            // bytes, copied on every anchor byte of the input otherwise.
            let Some(anchor) = &self.anchors[i] else {
                continue;
            };
            if !anchor.bytes.contains(cur) || pos < state.pos(i) {
                continue;
            }
            // A cheap confirmation before any walk: the first anchor byte
            // of a match has a known byte at a fixed offset.
            let mut confirmed = false;
            if let Some(check) = anchor
                .checks
                .iter()
                .flatten()
                .find(|check| check.anchors.contains(cur))
            {
                let seen = check.offsets().iter().any(|&offset| {
                    input
                        .get(pos + offset as usize)
                        .is_some_and(|&b| check.bytes.contains(b))
                });
                if !seen {
                    continue;
                }
                confirmed = true;
            }
            let tried = state.tried(i);
            if let Some(back) = anchor.back {
                // The match can only start `back` bytes before the anchor.
                let mut next_tried = pos + 1;
                if let Some(p) = pos.checked_sub(back as usize)
                    && p >= tried
                    && self.starts[i].contains(input[p])
                {
                    // A confirmed anchor at its exact offset is almost always
                    // a match: the finder validates it in one go, without the
                    // gates and rules it would pass anyway.
                    let matched = if confirmed {
                        self.call_finder_at(i, input, p, state, matches, probe)
                    } else {
                        self.try_finder_at(i, input, p, state, matches, probe)
                    };
                    if matched {
                        next_tried = next_tried.max(state.pos(i));
                    }
                }
                state.set_tried(i, next_tried);
                continue;
            }
            let mut start = pos;
            while start > tried && anchor.walk.contains(input[start - 1]) {
                start -= 1;
            }
            let mut p = start.max(tried);
            let mut next_tried = pos + 1;
            while p <= pos {
                if self.starts[i].contains(input[p])
                    && self.try_finder_at(i, input, p, state, matches, probe)
                {
                    next_tried = next_tried.max(state.pos(i));
                    break;
                }
                p += 1;
            }
            state.set_tried(i, next_tried);
        }
    }

    /// Calls finder `i` at `pos` without any gate or rule (they are only
    /// necessary conditions, so skipping them changes nothing but the
    /// cost). Returns whether a match was recorded.
    #[inline]
    fn call_finder_at<P: Probe>(
        &self,
        i: usize,
        input: &[u8],
        pos: usize,
        state: &mut LineState,
        matches: &mut Vec<Match>,
        probe: &mut P,
    ) -> bool {
        probe.candidate_position();
        let found = self.finders[i].try_at_memo(input, pos, state.memo(i));
        probe.try_at_call(i, found.is_some());
        match found {
            Some(range) if range.start >= state.pos(i) => {
                state.set_pos(i, range.end);
                probe.matched(i);
                matches.push(Match {
                    finder_index: i,
                    range,
                });
                true
            }
            _ => false,
        }
    }

    /// Dispatch attempt of finder `i` at `pos` with the exact gates and run
    /// rules applied first. Returns whether a match was recorded.
    #[inline]
    fn try_finder_at<P: Probe>(
        &self,
        i: usize,
        input: &[u8],
        pos: usize,
        state: &mut LineState,
        matches: &mut Vec<Match>,
        probe: &mut P,
    ) -> bool {
        let bit = 1u32 << i;
        let cur = input[pos];
        let prev_class = if pos > 0 {
            CTX_CLASS[input[pos - 1] as usize] as usize
        } else {
            CTX_NONE
        };
        let next_class = if pos + 1 < input.len() {
            CTX_CLASS[input[pos + 1] as usize] as usize
        } else {
            CTX_NONE
        };
        if self.gate_prev[prev_class][cur as usize] & self.gate_next[cur as usize][next_class] & bit
            == 0
        {
            return false;
        }
        probe.candidate_position();
        if self.word_mask & bit != 0 {
            let runs = Runs::only_word(Runs::word_at(input, pos, self.word_cap));
            if !RunRule::allow(&self.run_rules[i], cur, &runs, input, pos) {
                probe.run_gated();
                return false;
            }
        }
        if self.run_mask & self.rule_cur[cur as usize] & bit != 0 {
            let runs = Runs::at_cached(input, pos, &mut state.runs, self.run_cap);
            if self.may_accept(&runs) & bit == 0
                || !RunRule::allow(&self.run_rules[i], cur, &runs, input, pos)
            {
                probe.run_gated();
                return false;
            }
        }
        let found = self.finders[i].try_at_memo(input, pos, state.memo(i));
        probe.try_at_call(i, found.is_some());
        match found {
            Some(range) if range.start >= state.pos(i) => {
                state.set_pos(i, range.end);
                probe.matched(i);
                matches.push(Match {
                    finder_index: i,
                    range,
                });
                true
            }
            _ => false,
        }
    }

    /// Finders at least one of whose digit or hex rules may accept `runs`,
    /// judged by the byte after each run alone.
    #[inline(always)]
    fn may_accept(&self, runs: &Runs) -> u32 {
        let index = |run: &crate::Run| run.after.map_or(256, |b| b as usize);
        let mut may = (self.after_digit[index(&runs.digit)]
            & self.len_digit[runs.digit.len as usize])
            | (self.after_hex[index(&runs.hex)] & self.len_hex[runs.hex.len as usize]);
        if runs.digit.capped {
            may |= self.digit_ruled & self.len_digit[runs.digit.len as usize];
        }
        if runs.hex.capped {
            may |= self.hex_ruled & self.len_hex[runs.hex.len as usize];
        }
        may
    }

    /// Drops the candidates whose word rules reject the word run at `pos`.
    /// Kept out of line: word rules are rare and the run measurement would
    /// bloat the candidate loop.
    #[inline(never)]
    fn word_gate<P: Probe>(
        &self,
        input: &[u8],
        pos: usize,
        mut candidates: u32,
        probe: &mut P,
    ) -> u32 {
        let runs = Runs::only_word(Runs::word_at(input, pos, self.word_cap));
        let mut gated = candidates & self.word_mask;
        while gated != 0 {
            let i = gated.trailing_zeros() as usize;
            gated &= gated - 1;
            if !RunRule::allow(&self.run_rules[i], input[pos], &runs, input, pos) {
                candidates &= !(1u32 << i);
                probe.run_gated();
            }
        }
        candidates
    }

    /// Invokes the finders in `candidates` at `pos`.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn invoke<P: Probe>(
        &self,
        input: &[u8],
        pos: usize,
        mut candidates: u32,
        state: &mut LineState,
        matches: &mut Vec<Match>,
        probe: &mut P,
        hint: Option<&RunHint<'_>>,
    ) {
        if candidates & self.word_mask != 0 {
            candidates = self.word_gate(input, pos, candidates, probe);
        }
        let ruled = candidates & self.run_mask & self.rule_cur[input[pos] as usize];
        if ruled != 0 {
            let runs = match hint {
                Some(hint) => Runs::at_hinted(input, pos, hint, &mut state.runs, self.run_cap),
                None => Runs::at_cached(input, pos, &mut state.runs, self.run_cap),
            };
            // Finders none of whose rules can accept the byte after the run
            // are dropped without visiting their rules.
            let may = self.may_accept(&runs);
            let rejected = ruled & !may;
            candidates &= !rejected;
            probe.run_gated_n(rejected.count_ones());
            let mut gated = ruled & may;
            while gated != 0 {
                let i = gated.trailing_zeros() as usize;
                gated &= gated - 1;
                if !RunRule::allow(&self.run_rules[i], input[pos], &runs, input, pos) {
                    candidates &= !(1u32 << i);
                    probe.run_gated();
                }
            }
        }
        while candidates != 0 {
            let i = candidates.trailing_zeros() as usize;
            candidates &= candidates - 1;

            if pos < state.pos(i) {
                continue;
            }
            let found = if self.dispatch_mask & (1u32 << i) != 0 {
                let found = self.finders[i].try_at_memo(input, pos, state.memo(i));
                probe.try_at_call(i, found.is_some());
                found
            } else {
                let found = self.finders[i].try_trigger_at_memo(input, pos, state.memo(i));
                probe.try_trigger_call(i, found.is_some());
                found
            };
            if let Some(range) = found {
                // Trigger matches can extend backward past the previous
                // match for this finder (e.g. an email local part walked
                // back across it); matches must stay disjoint per finder.
                if range.start < state.pos(i) {
                    continue;
                }
                state.set_pos(i, range.end);
                probe.matched(i);
                matches.push(Match {
                    finder_index: i,
                    range,
                });
            }
        }
    }

    /// `Strategy::Gated`: one pass, context-gated candidates.
    fn walk_gated<P: Probe>(
        &self,
        input: &[u8],
        active: u32,
        matches: &mut Vec<Match>,
        probe: &mut P,
    ) {
        let active_ctx = active & (self.dispatch_mask | self.trigger_mask);
        if active_ctx == 0 {
            return;
        }
        let mut state = LineState::new(self.finders.len());
        probe.positions(input.len());
        let len = input.len();
        let mut prev_class = CTX_NONE;

        for pos in 0..len {
            let cur = input[pos];
            let mut candidates = self.gate_prev[prev_class][cur as usize] & active_ctx;
            prev_class = CTX_CLASS[cur as usize] as usize;
            if candidates == 0 {
                continue;
            }
            let next_class = if pos + 1 < len {
                CTX_CLASS[input[pos + 1] as usize] as usize
            } else {
                CTX_NONE
            };
            candidates &= self.gate_next[cur as usize][next_class];
            if candidates == 0 {
                continue;
            }
            probe.candidate_position();
            self.invoke(input, pos, candidates, &mut state, matches, probe, None);
        }
    }

    /// `Strategy::Vector`: every pass over the line, then the exact gates.
    fn walk_vector<P: Probe>(
        &self,
        input: &[u8],
        active: u32,
        matches: &mut Vec<Match>,
        probe: &mut P,
    ) {
        let active_ctx = active & (self.dispatch_mask | self.trigger_mask);
        if active_ctx == 0 {
            return;
        }
        probe.positions(input.len());
        let mut sink = LineSink {
            input,
            active_ctx,
            state: LineState::new(self.finders.len()),
            matches,
            probe,
        };
        for pass in &self.passes {
            if active_ctx & pass.finders != 0 {
                self.walk_pass(pass, input, &mut sink);
            }
        }
    }

    /// Runs the search of `pass` over `input` and hands every candidate to
    /// `sink`.
    #[inline(always)]
    fn walk_pass<S: Sink>(&self, pass: &Pass, input: &[u8], sink: &mut S) {
        match pass.search {
            Search::One(a) => {
                for pos in memchr::memchr_iter(a, input) {
                    sink.candidate(self, pass, pos, None);
                    if sink.stopped() {
                        return;
                    }
                }
            }
            Search::Two(a, b) => {
                for pos in memchr::memchr2_iter(a, b, input) {
                    sink.candidate(self, pass, pos, None);
                    if sink.stopped() {
                        return;
                    }
                }
            }
            Search::Three(a, b, c) => {
                for pos in memchr::memchr3_iter(a, b, c, input) {
                    sink.candidate(self, pass, pos, None);
                    if sink.stopped() {
                        return;
                    }
                }
            }
            Search::Blocks => {
                if input.len() < BLOCK {
                    // Shorter than a block: the table walk has no setup.
                    let mut prev_class = CTX_NONE;
                    for (pos, &cur) in input.iter().enumerate() {
                        let candidates = self.gate_prev[prev_class][cur as usize] & pass.finders;
                        prev_class = CTX_CLASS[cur as usize] as usize;
                        if candidates != 0 {
                            sink.candidate(self, pass, pos, None);
                            if sink.stopped() {
                                return;
                            }
                        }
                    }
                    return;
                }
                match self.backend {
                    classify::Kind::Scalar => {
                        self.walk_blocks::<classify::Scalar, S>(pass, input, sink)
                    }
                    #[cfg(target_arch = "aarch64")]
                    classify::Kind::Neon => {
                        self.walk_blocks::<classify::neon::Neon, S>(pass, input, sink)
                    }
                    #[cfg(target_arch = "x86_64")]
                    classify::Kind::Ssse3 => {
                        // SAFETY: `Kind::Ssse3` is only selected after the CPU check.
                        unsafe { self.walk_blocks_ssse3(pass, input, sink) }
                    }
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn walk_blocks_ssse3<S: Sink>(&self, pass: &Pass, input: &[u8], sink: &mut S) {
        self.walk_blocks::<classify::ssse3::Ssse3, S>(pass, input, sink)
    }

    #[inline(always)]
    fn walk_blocks<B: Backend, S: Sink>(&self, pass: &Pass, input: &[u8], sink: &mut S) {
        const GROUP: usize = 4;
        let rules = pass.rules.as_ref().expect("a block pass has rules");
        let tables = B::tables(rules);
        let len = input.len();
        debug_assert!(len >= BLOCK);
        let block_at =
            |at: usize| -> &[u8; BLOCK] { input[at..at + BLOCK].try_into().expect("a full block") };
        let cat_at =
            |at: usize| -> u8 { input.get(at).map_or(CAT_NONE, |&b| CATEGORY[b as usize]) };

        let mut base = 0;
        // Groups of four independent blocks: one emptiness test skips 64
        // bytes, and the four chains overlap in the pipeline.
        while base + GROUP * BLOCK <= len {
            let prev = if base == 0 {
                CAT_NONE
            } else {
                cat_at(base - 1)
            };
            let l0 = B::block(&tables, rules, block_at(base), prev, cat_at(base + BLOCK));
            let l1 = B::block(
                &tables,
                rules,
                block_at(base + BLOCK),
                cat_at(base + BLOCK - 1),
                cat_at(base + 2 * BLOCK),
            );
            let l2 = B::block(
                &tables,
                rules,
                block_at(base + 2 * BLOCK),
                cat_at(base + 2 * BLOCK - 1),
                cat_at(base + 3 * BLOCK),
            );
            let l3 = B::block(
                &tables,
                rules,
                block_at(base + 3 * BLOCK),
                cat_at(base + 3 * BLOCK - 1),
                cat_at(base + 4 * BLOCK),
            );
            let mut lanes = [l0, l1, l2, l3];
            if pass.min_hex_run >= 2 {
                classify::drop_short_hex_runs::<B>(&mut lanes, pass.min_hex_run);
            }
            let any = B::or(
                B::or(lanes[0].cand, lanes[1].cand),
                B::or(lanes[2].cand, lanes[3].cand),
            );
            if !B::is_zero(any) {
                self.probe_group::<B, S>(pass, base, &lanes, 0, sink);
                if sink.stopped() {
                    return;
                }
            }
            base += GROUP * BLOCK;
        }
        // Remaining full blocks, one at a time.
        while base + BLOCK <= len {
            let prev = if base == 0 {
                CAT_NONE
            } else {
                cat_at(base - 1)
            };
            let mut lanes = [B::block(
                &tables,
                rules,
                block_at(base),
                prev,
                cat_at(base + BLOCK),
            )];
            if pass.min_hex_run >= 2 {
                classify::drop_short_hex_runs::<B>(&mut lanes, pass.min_hex_run);
            }
            if !B::is_zero(lanes[0].cand) {
                self.probe_group::<B, S>(pass, base, &lanes, 0, sink);
                if sink.stopped() {
                    return;
                }
            }
            base += BLOCK;
        }
        // Tail: re-classify the last full block, which overlaps the bytes
        // already walked, and keep only the lanes past `base`. No copy.
        if base < len {
            let at = len - BLOCK;
            let mut lanes = [B::block(
                &tables,
                rules,
                block_at(at),
                cat_at(at.wrapping_sub(1)),
                CAT_NONE,
            )];
            if pass.min_hex_run >= 2 {
                classify::drop_short_hex_runs::<B>(&mut lanes, pass.min_hex_run);
            }
            if !B::is_zero(lanes[0].cand) {
                self.probe_group::<B, S>(pass, at, &lanes, base - at, sink);
            }
        }
    }

    /// Probes every candidate lane of the blocks in `lanes` (contiguous
    /// from `base`), ignoring the first `skip` lanes.
    #[inline(always)]
    fn probe_group<B: Backend, S: Sink>(
        &self,
        pass: &Pass,
        base: usize,
        lanes: &[Lanes<B::Vec>],
        skip: usize,
        sink: &mut S,
    ) {
        let mut hex = [0u64; 4];
        let mut digit = [0u64; 4];
        let mut cand = [0u64; 4];
        let count = lanes.len().min(4);
        for (i, l) in lanes.iter().take(count).enumerate() {
            cand[i] = B::mask(l.cand);
            hex[i] = B::mask(l.hex);
            digit[i] = B::mask(l.digit);
        }
        cand[0] &= !B::lanes(skip);
        for i in 0..count {
            let mut mask = cand[i];
            while mask != 0 {
                let lane = B::lane(mask);
                mask = B::clear(mask, lane);
                let hint = RunHint {
                    hex: &hex[i..count],
                    digit: &digit[i..count],
                    lane,
                    stride: B::STRIDE,
                };
                sink.candidate(self, pass, base + i * BLOCK + lane, Some(&hint));
                if sink.stopped() {
                    return;
                }
            }
        }
    }

    /// Scans every line of `text` in one pass over the buffer and calls
    /// `emit(line_start, line_end, matches)` for each line with at least one
    /// match, in order; `line_end` excludes the terminator and trailing
    /// `\r`s, and the match ranges are relative to `line_start`, exactly as
    /// [`scan_line`](Self::scan_line) would report them for that line.
    /// Returns `true` when `emit` asked to stop.
    ///
    /// With the vector strategy and no scan-mode finder the candidate search
    /// runs over the whole buffer and only lines holding a candidate are
    /// looked at, which is much cheaper than a call per line.
    pub fn scan_buffer(
        &self,
        text: &str,
        mut emit: impl FnMut(usize, usize, &[Match]) -> bool,
    ) -> bool {
        let data = text.as_bytes();
        if self.strategy != Strategy::Vector || self.scan_mask != 0 || self.passes.is_empty() {
            return self.scan_lines(text, &mut emit);
        }
        if let [pass] = self.passes.as_slice() {
            if pass.whole {
                let mut matches = Vec::new();
                let mut sink = WholeSink {
                    data,
                    state: LineState::new(self.finders.len()),
                    matches: &mut matches,
                };
                self.walk_pass(pass, data, &mut sink);
                sort_matches(&mut matches);
                return emit_grouped(data, matches, &mut emit);
            }
            let mut sink = BufferSink::new(data, self, Stream(&mut emit));
            self.walk_pass(pass, data, &mut sink);
            sink.flush();
            return sink.stopped;
        }
        // Several passes: absolute matches per pass, merged into `scan_line`
        // order and grouped per line.
        let mut lists = Vec::with_capacity(self.passes.len());
        for pass in &self.passes {
            let mut matches = Vec::new();
            if pass.whole {
                let mut sink = WholeSink {
                    data,
                    state: LineState::new(self.finders.len()),
                    matches: &mut matches,
                };
                self.walk_pass(pass, data, &mut sink);
            } else {
                let mut sink = BufferSink::new(data, self, Collect(&mut matches));
                self.walk_pass(pass, data, &mut sink);
                sink.flush();
            }
            sort_matches(&mut matches);
            lists.push(matches);
        }
        emit_grouped(data, merge_matches(lists), &mut emit)
    }

    /// Scans `text` like [`scan_buffer`](Self::scan_buffer) but hands every
    /// match to `emit(finder_index, range)` with a range into `text`, in the
    /// same order (by start, then finder), without resolving the lines
    /// around them; a caller that prints values alone skips that work.
    /// Returns `true` when `emit` asked to stop.
    pub fn scan_buffer_matches(
        &self,
        text: &str,
        mut emit: impl FnMut(usize, Range<usize>) -> bool,
    ) -> bool {
        let data = text.as_bytes();
        if self.strategy != Strategy::Vector || self.scan_mask != 0 || self.passes.is_empty() {
            return self.scan_lines(text, &mut |start, _end, matches: &[Match]| {
                matches
                    .iter()
                    .any(|m| emit(m.finder_index, m.range.start + start..m.range.end + start))
            });
        }
        let mut lists = Vec::with_capacity(self.passes.len());
        for pass in &self.passes {
            let mut matches = Vec::new();
            if pass.whole {
                let mut sink = WholeSink {
                    data,
                    state: LineState::new(self.finders.len()),
                    matches: &mut matches,
                };
                self.walk_pass(pass, data, &mut sink);
            } else {
                let mut sink = BufferSink::new(data, self, Collect(&mut matches));
                self.walk_pass(pass, data, &mut sink);
                sink.flush();
            }
            sort_matches(&mut matches);
            lists.push(matches);
        }
        merge_matches(lists)
            .into_iter()
            .any(|m| emit(m.finder_index, m.range))
    }

    /// Line-by-line scanning of `text`, for every strategy.
    fn scan_lines(
        &self,
        text: &str,
        emit: &mut impl FnMut(usize, usize, &[Match]) -> bool,
    ) -> bool {
        let data = text.as_bytes();
        let mut matches = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let nl = memchr::memchr(b'\n', &data[pos..]).map_or(data.len(), |i| pos + i);
            let mut end = nl;
            while end > pos && data[end - 1] == b'\r' {
                end -= 1;
            }
            self.scan_line_into(&text[pos..end], &mut matches);
            if !matches.is_empty() && emit(pos, end, &matches) {
                return true;
            }
            pos = nl + 1;
        }
        false
    }

    /// Returns the same match as `scan_line(line).into_iter().next()`: the
    /// earliest-starting match, ties broken by the lowest finder index.
    pub fn scan_line_first(&self, line: &str) -> Option<Match> {
        let input = line.as_bytes();
        let active = self.activate(input, &mut ())?;

        let mut best: Option<Match> = None;
        // Matches scan_line's sort order: (range.start, finder_index) ascending.
        let beats = |best: &Option<Match>, start: usize, index: usize| match best {
            None => true,
            Some(b) => (start, index) < (b.range.start, b.finder_index),
        };

        let active_scan = active & self.scan_mask;
        if active_scan != 0 {
            let mut bits = active_scan;
            while bits != 0 {
                let i = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                if let Some(range) = self.finders[i].find(line)
                    && beats(&best, range.start, i)
                {
                    best = Some(Match {
                        finder_index: i,
                        range,
                    });
                }
            }
        }

        let active_ctx = active & (self.dispatch_mask | self.trigger_mask);
        if active_ctx != 0 {
            let mut state = LineState::new(self.finders.len());
            let len = input.len();
            let mut prev_class = CTX_NONE;
            let mut allowed = active_ctx;

            for pos in 0..len {
                // Dispatch matches start at `pos`, so once `pos` passes the best
                // start no dispatch candidate can win (ties at equal start still
                // can). Trigger matches can start before their trigger byte, so
                // those finders must keep visiting every position.
                if allowed & self.dispatch_mask != 0
                    && let Some(b) = &best
                    && pos > b.range.start
                {
                    allowed &= self.trigger_mask;
                    if allowed == 0 {
                        break;
                    }
                }
                let cur = input[pos];
                let mut candidates = self.gate_prev[prev_class][cur as usize] & allowed;
                prev_class = CTX_CLASS[cur as usize] as usize;
                if candidates == 0 {
                    continue;
                }
                let next_class = if pos + 1 < len {
                    CTX_CLASS[input[pos + 1] as usize] as usize
                } else {
                    CTX_NONE
                };
                candidates &= self.gate_next[cur as usize][next_class];
                if candidates & self.word_mask != 0 {
                    let runs = Runs::only_word(Runs::word_at(input, pos, self.word_cap));
                    let mut gated = candidates & self.word_mask;
                    while gated != 0 {
                        let i = gated.trailing_zeros() as usize;
                        gated &= gated - 1;
                        if !RunRule::allow(&self.run_rules[i], cur, &runs, input, pos) {
                            candidates &= !(1u32 << i);
                        }
                    }
                }
                let ruled = candidates & self.run_mask & self.rule_cur[cur as usize];
                if ruled != 0 {
                    let runs = Runs::at_cached(input, pos, &mut state.runs, self.run_cap);
                    let may = self.may_accept(&runs);
                    candidates &= !(ruled & !may);
                    let mut gated = ruled & may;
                    while gated != 0 {
                        let i = gated.trailing_zeros() as usize;
                        gated &= gated - 1;
                        if !RunRule::allow(&self.run_rules[i], cur, &runs, input, pos) {
                            candidates &= !(1u32 << i);
                        }
                    }
                }
                while candidates != 0 {
                    let i = candidates.trailing_zeros() as usize;
                    candidates &= candidates - 1;

                    if pos < state.pos(i) {
                        continue;
                    }
                    let found = if self.dispatch_mask & (1u32 << i) != 0 {
                        self.finders[i].try_at_memo(input, pos, state.memo(i))
                    } else {
                        self.finders[i].try_trigger_at_memo(input, pos, state.memo(i))
                    };
                    if let Some(range) = found {
                        if range.start < state.pos(i) {
                            continue;
                        }
                        state.set_pos(i, range.end);
                        if beats(&best, range.start, i) {
                            best = Some(Match {
                                finder_index: i,
                                range,
                            });
                        }
                    }
                }
            }
        }

        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prescan_empty_input() {
        assert_eq!(prescan(b""), 0);
    }

    #[test]
    fn prescan_detects_digit() {
        assert_ne!(prescan(b"abc123") & CL_DIGIT, 0);
    }

    #[test]
    fn prescan_detects_at() {
        assert_ne!(prescan(b"user@host") & CL_AT, 0);
    }

    #[test]
    fn prescan_detects_dollar() {
        assert_ne!(prescan(b"$HOME") & CL_DOLLAR, 0);
    }

    #[test]
    fn prescan_no_false_positives() {
        let cl = prescan(b"hello world");
        assert_eq!(cl & CL_AT, 0);
        assert_eq!(cl & CL_DOLLAR, 0);
        assert_eq!(cl & CL_DIGIT, 0);
    }

    #[test]
    fn can_skip_email_without_at() {
        let cl = prescan(b"hello world");
        assert!(can_skip_with_mask(cl, required_classes("email")));
    }

    #[test]
    fn cannot_skip_email_with_at() {
        let cl = prescan(b"user@example.com");
        assert!(!can_skip_with_mask(cl, required_classes("email")));
    }

    #[test]
    fn can_skip_env_without_dollar() {
        let cl = prescan(b"no vars here");
        assert!(can_skip_with_mask(cl, required_classes("env")));
    }

    #[test]
    fn can_skip_json_without_brackets() {
        let cl = prescan(b"no json here");
        assert!(can_skip_with_mask(cl, required_classes("json")));
    }

    #[test]
    fn can_skip_uri_without_colon() {
        let cl = prescan(b"no uris here");
        assert!(can_skip_with_mask(cl, required_classes("uri")));
    }

    #[test]
    fn can_skip_uuid_without_dash() {
        let cl = prescan(b"abcdef1234567890");
        assert!(can_skip_with_mask(cl, required_classes("uuid")));
    }

    #[test]
    fn cannot_skip_mirror() {
        let cl = prescan(b"anything");
        assert!(!can_skip_with_mask(cl, required_classes("mirror")));
    }

    #[test]
    fn can_skip_hash_without_hex() {
        let cl = prescan(b"no hx zzz");
        assert!(can_skip_with_mask(cl, required_classes("hash")));
    }

    #[test]
    fn can_skip_mac_without_separator() {
        let cl = prescan(b"aabbccddeeff");
        assert!(can_skip_with_mask(cl, required_classes("mac")));
    }

    #[test]
    fn can_skip_semver_without_dot() {
        let cl = prescan(b"version 100");
        assert!(can_skip_with_mask(cl, required_classes("semver")));
    }

    #[test]
    fn can_skip_cidr_without_slash() {
        let cl = prescan(b"192.168.1.0");
        assert!(can_skip_with_mask(cl, required_classes("cidr")));
    }

    #[test]
    fn can_skip_path_without_prefix() {
        let cl = prescan(b"no paths here");
        assert!(can_skip_with_mask(cl, required_classes("path")));
    }

    #[test]
    fn skip_to_candidate_line_jumps_over_lines_without_start_bytes() {
        let scanner = Scanner::new(vec![Box::new(crate::email::Email::default())]);
        let text = b"no mail\nstill none\nhi a@b.co there\ntail";
        assert_eq!(scanner.skip_to_candidate_line(text, 0), Some(19));
        assert_eq!(scanner.skip_to_candidate_line(text, 19), Some(19));
        assert_eq!(scanner.skip_to_candidate_line(text, 34), None);
        assert_eq!(scanner.skip_to_candidate_line(text, 100), None);
        let scanner = Scanner::new(vec![Box::new(crate::hash::Hash::default())]);
        assert_eq!(scanner.skip_to_candidate_line(text, 8), Some(8));
    }

    #[test]
    fn sparse_scanner_matches_prescanned_results() {
        let text = "mail a@b.co, url http://x.y, none";
        let finders = || -> Vec<Box<dyn Finder>> {
            vec![
                Box::new(crate::email::Email::default()),
                Box::new(crate::uri::URI::default()),
            ]
        };
        let mut gated = Scanner::new(finders());
        gated.set_strategy(Strategy::Gated);
        let vector = Scanner::new(finders());
        assert_eq!(gated.scan_line(text), vector.scan_line(text));
        assert_eq!(gated.scan_line("nothing"), vector.scan_line("nothing"));
    }

    #[test]
    fn scanner_empty_finders() {
        let scanner = Scanner::new(Vec::new());
        assert!(scanner.scan_line("hello").is_empty());
    }

    #[test]
    fn scanner_try_new_rejects_too_many_finders() {
        let finders: Vec<Box<dyn Finder>> = (0..=MAX_FINDERS)
            .map(|_| Box::new(crate::mirror::Mirror::default()) as Box<dyn Finder>)
            .collect();
        assert!(matches!(
            Scanner::try_new(finders),
            Err(ScannerError::TooManyFinders {
                len,
                max,
            })
            if len == MAX_FINDERS + 1 && max == MAX_FINDERS
        ));
    }

    #[test]
    fn scanner_empty_line() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::mirror::Mirror::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("").is_empty());
    }

    #[test]
    fn scanner_mirror_matches_everything() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::mirror::Mirror::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line("hello world");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].range, 0..11);
    }

    #[test]
    fn scanner_prescan_skips_impossible_finders() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::email::Email::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line("no at sign here");
        assert!(matches.is_empty());
    }

    #[test]
    fn scanner_dispatch_finds_hash() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::hash::Hash::default())];
        let scanner = Scanner::new(finders);
        let input = "md5: 5d41402abc4b2a76b9719d911017c592";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].range.clone()],
            "5d41402abc4b2a76b9719d911017c592"
        );
    }

    #[test]
    fn scanner_dispatch_finds_multiple_hashes() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::hash::Hash::default())];
        let scanner = Scanner::new(finders);
        let input = "5d41402abc4b2a76b9719d911017c592 and 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert_eq!(
            &input[matches[0].range.clone()],
            "5d41402abc4b2a76b9719d911017c592"
        );
        assert_eq!(
            &input[matches[1].range.clone()],
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        );
    }

    #[test]
    fn scanner_mixed_dispatch_and_scan() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::email::Email::default()),
        ];
        let scanner = Scanner::new(finders);
        let input = "user@example.com 5d41402abc4b2a76b9719d911017c592";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert_eq!(&input[matches[0].range.clone()], "user@example.com");
        assert_eq!(
            &input[matches[1].range.clone()],
            "5d41402abc4b2a76b9719d911017c592"
        );
    }

    #[test]
    fn scanner_position_ordered_output() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::env::Env::default()),
            Box::new(crate::hash::Hash::default()),
        ];
        let scanner = Scanner::new(finders);
        let input = "5d41402abc4b2a76b9719d911017c592 $HOME";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert!(matches[0].range.start < matches[1].range.start);
    }

    #[test]
    fn scanner_first_returns_earliest() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::env::Env::default()),
            Box::new(crate::hash::Hash::default()),
        ];
        let scanner = Scanner::new(finders);
        let input = "$HOME then 5d41402abc4b2a76b9719d911017c592";
        let m = scanner.scan_line_first(input).unwrap();
        assert_eq!(&input[m.range], "$HOME");
    }

    #[test]
    fn scanner_dispatch_finds_env() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        let input = "use $HOME and ${PATH}";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert_eq!(&input[matches[0].range.clone()], "$HOME");
        assert_eq!(&input[matches[1].range.clone()], "${PATH}");
    }

    #[test]
    fn scanner_dispatch_finds_json() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::json::Json::default())];
        let scanner = Scanner::new(finders);
        let input = r#"data: {"key": "value"} end"#;
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].range.clone()], r#"{"key": "value"}"#);
    }

    #[test]
    fn scanner_dispatch_finds_uuid() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::uuid::Uuid::default())];
        let scanner = Scanner::new(finders);
        let input = "id: 550e8400-e29b-41d4-a716-446655440000 end";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].range.clone()],
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn scanner_dispatch_finds_color() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::color::Color::default())];
        let scanner = Scanner::new(finders);
        let input = "color: #ff00aa and rgb(0, 255, 0)";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 2);
        assert_eq!(&input[matches[0].range.clone()], "#ff00aa");
        assert_eq!(&input[matches[1].range.clone()], "rgb(0, 255, 0)");
    }

    #[test]
    fn scanner_dispatch_finds_ip() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::ip::Ip::default())];
        let scanner = Scanner::new(finders);
        let input = "connect to 192.168.1.1 now";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].range.clone()], "192.168.1.1");
    }

    #[test]
    fn scanner_dispatch_finds_datetime() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::datetime::Datetime::default())];
        let scanner = Scanner::new(finders);
        let input = "at 2024-01-15T10:30:00Z end";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].range.clone()], "2024-01-15T10:30:00Z");
    }

    #[test]
    fn scanner_many_finders() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::email::Email::default()),
            Box::new(crate::env::Env::default()),
            Box::new(crate::json::Json::default()),
            Box::new(crate::ip::Ip::default()),
        ];
        let scanner = Scanner::new(finders);
        let input =
            r#"192.168.1.1 user@example.com $HOME {"key": "val"} 5d41402abc4b2a76b9719d911017c592"#;
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 5);
        assert_eq!(&input[matches[0].range.clone()], "192.168.1.1");
        assert_eq!(&input[matches[1].range.clone()], "user@example.com");
        assert_eq!(&input[matches[2].range.clone()], "$HOME");
        assert_eq!(&input[matches[3].range.clone()], r#"{"key": "val"}"#);
        assert_eq!(
            &input[matches[4].range.clone()],
            "5d41402abc4b2a76b9719d911017c592"
        );
    }

    // --- Edge cases: single byte inputs ---

    #[test]
    fn scanner_single_byte_inputs() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::email::Email::default()),
            Box::new(crate::env::Env::default()),
            Box::new(crate::ip::Ip::default()),
            Box::new(crate::json::Json::default()),
            Box::new(crate::color::Color::default()),
            Box::new(crate::uuid::Uuid::default()),
        ];
        let scanner = Scanner::new(finders);
        for b in 0..=127u8 {
            let s = String::from(b as char);
            let _ = scanner.scan_line(&s);
        }
    }

    #[test]
    fn scanner_two_byte_combinations() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::env::Env::default()),
            Box::new(crate::json::Json::default()),
            Box::new(crate::color::Color::default()),
        ];
        let scanner = Scanner::new(finders);
        let interesting = b"${}[]#rgb()0aA@:/.~+-\"\\";
        for &a in interesting {
            for &b in interesting {
                let s = String::from_utf8(vec![a, b]).unwrap();
                let _ = scanner.scan_line(&s);
            }
        }
    }

    // --- Edge cases: repeated delimiters ---

    #[test]
    fn scanner_repeated_dollars() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("$$$").is_empty());
        assert!(scanner.scan_line("$$$$").is_empty());
    }

    #[test]
    fn scanner_repeated_hashes() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::color::Color::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("###").is_empty());
    }

    #[test]
    fn scanner_repeated_brackets() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::json::Json::default())];
        let scanner = Scanner::new(finders);
        let matches = scanner.scan_line("{}{}{}");
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn scanner_repeated_dots() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::ip::Ip::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("....").is_empty());
    }

    // --- Edge cases: only whitespace ---

    #[test]
    fn scanner_whitespace() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::email::Email::default()),
        ];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line("   \t\n  ").is_empty());
    }

    // --- Edge cases: very long lines ---

    #[test]
    fn scanner_long_hex_run() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::hash::Hash::default())];
        let scanner = Scanner::new(finders);
        let long_hex = "a".repeat(10000);
        assert!(scanner.scan_line(&long_hex).is_empty());
    }

    #[test]
    fn scanner_many_matches_in_line() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        let input = (0..100)
            .map(|i| format!("$VAR{}", i))
            .collect::<Vec<_>>()
            .join(" ");
        let matches = scanner.scan_line(&input);
        assert_eq!(matches.len(), 100);
    }

    // --- Edge cases: adjacent matches ---

    #[test]
    fn scanner_adjacent_env_vars() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        let input = "$A$B$C";
        let matches = scanner.scan_line(input);
        let texts: Vec<&str> = matches.iter().map(|m| &input[m.range.clone()]).collect();
        assert_eq!(texts, vec!["$A", "$B", "$C"]);
    }

    #[test]
    fn scanner_adjacent_json_objects() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::json::Json::default())];
        let scanner = Scanner::new(finders);
        let input = r#"{"a":1}{"b":2}[3]"#;
        let matches = scanner.scan_line(input);
        let texts: Vec<&str> = matches.iter().map(|m| &input[m.range.clone()]).collect();
        assert_eq!(texts, vec![r#"{"a":1}"#, r#"{"b":2}"#, "[3]"]);
    }

    // --- Edge cases: prescan correctness ---

    #[test]
    fn prescan_all_byte_classes() {
        let input = b"09afAF gZ@$#{}[]:./~+(- ";
        let cl = prescan(input);
        assert_ne!(cl & CL_DIGIT, 0);
        assert_ne!(cl & CL_HEX_ALPHA, 0);
        assert_ne!(cl & CL_ALPHA_OTHER, 0);
        assert_ne!(cl & CL_AT, 0);
        assert_ne!(cl & CL_DOLLAR, 0);
        assert_ne!(cl & CL_HASH, 0);
        assert_ne!(cl & CL_OPEN_BRACE, 0);
        assert_ne!(cl & CL_OPEN_BRACKET, 0);
        assert_ne!(cl & CL_COLON, 0);
        assert_ne!(cl & CL_DOT, 0);
        assert_ne!(cl & CL_SLASH, 0);
        assert_ne!(cl & CL_TILDE, 0);
        assert_ne!(cl & CL_PLUS, 0);
        assert_ne!(cl & CL_OPEN_PAREN, 0);
        assert_ne!(cl & CL_DASH, 0);
    }

    #[test]
    fn prescan_high_bytes_have_no_class() {
        for b in 128..=255u8 {
            assert_eq!(
                BYTE_CLASSES[b as usize], 0,
                "byte {} should have no class",
                b
            );
        }
    }

    // --- Edge cases: dispatch table ---

    #[test]
    fn dispatch_table_env_only_dollar() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        for b in 0..=255u8 {
            if b == b'$' {
                assert_ne!(scanner.gate_prev[CTX_NONE][b as usize], 0);
            } else {
                assert_eq!(scanner.gate_prev[CTX_NONE][b as usize], 0);
            }
        }
    }

    #[test]
    fn dispatch_table_color_selective() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::color::Color::default())];
        let scanner = Scanner::new(finders);
        let start = &scanner.gate_prev[CTX_NONE];
        assert_ne!(start[b'#' as usize], 0);
        assert_ne!(start[b'r' as usize], 0);
        assert_ne!(start[b'R' as usize], 0);
        assert_ne!(start[b'h' as usize], 0);
        assert_ne!(start[b'H' as usize], 0);
        assert_eq!(start[b'x' as usize], 0);
        assert_eq!(start[b' ' as usize], 0);
        // `#` has no previous-byte rule; `r` must follow a non-alphanumeric.
        assert_ne!(scanner.gate_prev[ctx_class(b'x')][b'#' as usize], 0);
        assert_eq!(scanner.gate_prev[ctx_class(b'x')][b'r' as usize], 0);
        assert_ne!(scanner.gate_prev[ctx_class(b' ')][b'r' as usize], 0);
        // `r` must be followed by `g`, `#` by a hex digit.
        assert_ne!(scanner.gate_next[b'r' as usize][ctx_class(b'g')], 0);
        assert_eq!(scanner.gate_next[b'r' as usize][ctx_class(b'x')], 0);
        assert_eq!(scanner.gate_next[b'#' as usize][ctx_class(b'x')], 0);
    }

    #[test]
    fn scanner_scan_line_first_with_no_matches() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::email::Email::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line_first("no at sign").is_none());
    }

    #[test]
    fn scanner_scan_line_first_prescan_skip() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::email::Email::default())];
        let scanner = Scanner::new(finders);
        assert!(scanner.scan_line_first("no matches possible").is_none());
    }

    // --- Regression: prescan early exit with all classes ---

    #[test]
    fn prescan_early_exit_fires_with_all_classes() {
        let input = b"09afAF gZ@$#{}[]:./~+(- ";
        let cl = prescan(input);
        assert_eq!(cl, CL_ALL_USED);
    }

    #[test]
    fn prescan_early_exit_on_long_input() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"09afAF gZ@$#{}[]:./~+(- ");
        buf.extend_from_slice(&[b'x'; 10000]);
        let cl = prescan(&buf);
        assert_eq!(cl, CL_ALL_USED);
    }

    // --- Regression: can_skip_with_mask all_required distinction ---

    #[test]
    fn can_skip_all_required_single_bit_present() {
        let cl = CL_DIGIT | CL_SLASH;
        assert!(!can_skip_with_mask(
            cl,
            &[(CL_DIGIT, true), (CL_SLASH, true)]
        ));
    }

    #[test]
    fn can_skip_all_required_missing_one() {
        let cl = CL_DIGIT;
        assert!(can_skip_with_mask(
            cl,
            &[(CL_DIGIT, true), (CL_SLASH, true)]
        ));
    }

    #[test]
    fn can_skip_any_required_at_least_one() {
        let cl = CL_HASH;
        assert!(!can_skip_with_mask(
            cl,
            &[(CL_HASH | CL_ALPHA_OTHER, false)]
        ));
    }

    #[test]
    fn can_skip_any_required_none_present() {
        let cl = CL_DIGIT;
        assert!(can_skip_with_mask(cl, &[(CL_HASH | CL_ALPHA_OTHER, false)]));
    }

    #[test]
    fn can_skip_cidr_with_digit_but_no_slash() {
        let cl = CL_DIGIT | CL_DOT;
        assert!(can_skip_with_mask(cl, required_classes("cidr")));
    }

    #[test]
    fn can_skip_semver_with_digit_but_no_dot() {
        let cl = CL_DIGIT;
        assert!(can_skip_with_mask(cl, required_classes("semver")));
    }

    #[test]
    fn cannot_skip_semver_with_digit_and_dot() {
        let cl = CL_DIGIT | CL_DOT;
        assert!(!can_skip_with_mask(cl, required_classes("semver")));
    }

    // --- Regression: scan_line_into reuses buffer ---

    #[test]
    fn scan_line_into_reuses_buffer() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::env::Env::default())];
        let scanner = Scanner::new(finders);
        let mut buf = Vec::new();

        scanner.scan_line_into("$HOME here", &mut buf);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0].range, 0..5);

        scanner.scan_line_into("$PATH and $USER", &mut buf);
        assert_eq!(buf.len(), 2);

        scanner.scan_line_into("no vars", &mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn scan_line_into_matches_scan_line() {
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::email::Email::default()),
            Box::new(crate::env::Env::default()),
        ];
        let scanner = Scanner::new(finders);
        let input = "user@example.com $HOME 5d41402abc4b2a76b9719d911017c592";

        let from_scan_line = scanner.scan_line(input);
        let mut buf = Vec::new();
        scanner.scan_line_into(input, &mut buf);

        assert_eq!(from_scan_line.len(), buf.len());
        for (a, b) in from_scan_line.iter().zip(buf.iter()) {
            assert_eq!(a.range, b.range);
            assert_eq!(a.finder_index, b.finder_index);
        }
    }

    // --- Regression: trigger matches must stay disjoint per finder ---

    #[test]
    fn trigger_matches_never_overlap_per_finder() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::email::Email::default())];
        let scanner = Scanner::new(finders);
        for input in ["a@b.co@d.ef", "user@example.com@evil.org"] {
            let matches = scanner.scan_line(input);
            for w in matches.windows(2) {
                assert!(
                    w[1].range.start >= w[0].range.end,
                    "overlapping matches on {input:?}: {:?} vs {:?}",
                    w[0].range,
                    w[1].range
                );
            }
        }
    }

    #[test]
    fn trigger_overlap_suppressed_keeps_first_match() {
        let finders: Vec<Box<dyn Finder>> = vec![Box::new(crate::email::Email::default())];
        let scanner = Scanner::new(finders);
        let input = "user@example.com@evil.org";
        let matches = scanner.scan_line(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].range.clone()], "user@example.com");
    }

    // --- Regression: scan_line_first must agree with scan_line()[0] ---

    #[test]
    fn scan_line_first_ties_broken_by_finder_index() {
        // hash (dispatch mode, index 0) and mirror (scan mode, index 1) both
        // match at position 0; scan_line sorts ties by finder index, and
        // scan_line_first must agree instead of favoring scan-mode finders.
        let input = "5d41402abc4b2a76b9719d911017c592 tail";
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::mirror::Mirror::default()),
        ];
        let scanner = Scanner::new(finders);
        let all = scanner.scan_line(input);
        let first = scanner.scan_line_first(input).unwrap();
        assert_eq!(first.finder_index, all[0].finder_index);
        assert_eq!(first.range, all[0].range);
        assert_eq!(first.finder_index, 0);
    }

    #[test]
    fn scan_line_first_agrees_with_scan_line_across_orders() {
        let inputs = [
            "2024-01-15.example.com",
            "x 2024-01-15.example.com",
            "$HOME 5d41402abc4b2a76b9719d911017c592",
            "5d41402abc4b2a76b9719d911017c592 $HOME",
            "user@example.com $HOME",
        ];
        let build_finders = |reversed: bool| -> Vec<Box<dyn Finder>> {
            let mut v: Vec<Box<dyn Finder>> = vec![
                Box::new(crate::datetime::Datetime::default()),
                Box::new(crate::hash::Hash::default()),
                Box::new(crate::env::Env::default()),
                Box::new(crate::email::Email::default()),
                Box::new(crate::mirror::Mirror::default()),
            ];
            if reversed {
                v.reverse();
            }
            v
        };
        for reversed in [false, true] {
            let scanner = Scanner::new(build_finders(reversed));
            for input in inputs {
                let all = scanner.scan_line(input);
                let first = scanner.scan_line_first(input);
                match (all.first(), first) {
                    (None, None) => {}
                    (Some(a), Some(f)) => {
                        assert_eq!(a.range, f.range, "range mismatch on {input:?}");
                        assert_eq!(
                            a.finder_index, f.finder_index,
                            "finder mismatch on {input:?}"
                        );
                    }
                    (a, f) => panic!("presence mismatch on {input:?}: {a:?} vs {f:?}"),
                }
            }
        }
    }

    // --- Regression: all finders combined ---

    #[test]
    fn scanner_all_finders_no_panic() {
        let mut codetag = crate::codetag::Codetag::default();
        codetag.build_mnemonics_regex().unwrap();
        let finders: Vec<Box<dyn Finder>> = vec![
            Box::new(crate::cidr::Cidr::default()),
            Box::new(codetag),
            Box::new(crate::color::Color::default()),
            Box::new(crate::datetime::Datetime::default()),
            Box::new(crate::email::Email::default()),
            Box::new(crate::emoji::Emoji::default()),
            Box::new(crate::env::Env::default()),
            Box::new(crate::hash::Hash::default()),
            Box::new(crate::ip::Ip::default()),
            Box::new(crate::json::Json::default()),
            Box::new(crate::jwt::Jwt::default()),
            Box::new(crate::mac::Mac::default()),
            Box::new(crate::path::Path::default()),
            Box::new(crate::phone::Phone::default()),
            Box::new(crate::semver::Semver::default()),
            Box::new(crate::uri::URI::default()),
            Box::new(crate::uuid::Uuid::default()),
        ];
        let scanner = Scanner::new(finders);

        for input in [
            "",
            " ",
            "hello world",
            "user@example.com",
            "http://example.com",
            "$HOME /etc/hosts 192.168.1.0/24",
            "550e8400-e29b-41d4-a716-446655440000",
            r#"{"key": "value"} TODO: fix this"#,
            "v1.2.3 #ff00aa 2024-01-15T10:30:00Z",
            "00:1A:2B:3C:4D:5E +14155551234",
            "😀🎉 hello",
        ] {
            let _ = scanner.scan_line(input);
            let _ = scanner.scan_line_first(input);
        }
    }
}
