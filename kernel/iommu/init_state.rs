/// Private preparation gate for global IOMMU/DMA availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitPublicationPhase {
    PrivateReady,
    DmaHooksReady,
    TranslationReady,
    FaultSnapshotReady,
}

impl InitPublicationPhase {
    pub(crate) const fn after_dma_hooks(self) -> Option<Self> {
        match self {
            Self::PrivateReady => Some(Self::DmaHooksReady),
            _ => None,
        }
    }

    pub(crate) const fn after_translation(
        self,
        discovered: usize,
        constructed: usize,
        translated: usize,
    ) -> Option<Self> {
        if discovered == 0 || constructed != discovered || translated != discovered {
            return None;
        }
        match self {
            Self::DmaHooksReady => Some(Self::TranslationReady),
            _ => None,
        }
    }

    pub(crate) const fn after_fault_snapshot(self) -> Option<Self> {
        match self {
            Self::TranslationReady => Some(Self::FaultSnapshotReady),
            _ => None,
        }
    }

    pub(crate) const fn may_commit_ready(self) -> bool {
        matches!(self, Self::FaultSnapshotReady)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_hooks_all_units_then_fault_snapshot() {
        let private = InitPublicationPhase::PrivateReady;
        assert!(!private.may_commit_ready());
        let hooks = private.after_dma_hooks().unwrap();
        assert!(!hooks.may_commit_ready());
        let translated = hooks.after_translation(2, 2, 2).unwrap();
        assert!(!translated.may_commit_ready());
        assert!(translated
            .after_fault_snapshot()
            .unwrap()
            .may_commit_ready());
    }

    #[test]
    fn reordered_or_repeated_preparation_is_rejected() {
        let private = InitPublicationPhase::PrivateReady;
        assert_eq!(private.after_translation(1, 1, 1), None);
        assert_eq!(private.after_fault_snapshot(), None);
        let hooks = private.after_dma_hooks().unwrap();
        assert_eq!(hooks.after_dma_hooks(), None);
        assert_eq!(hooks.after_fault_snapshot(), None);
        let translated = hooks.after_translation(1, 1, 1).unwrap();
        assert_eq!(translated.after_dma_hooks(), None);
        assert_eq!(translated.after_translation(1, 1, 1), None);
        let snapshot = translated.after_fault_snapshot().unwrap();
        assert_eq!(snapshot.after_dma_hooks(), None);
        assert_eq!(snapshot.after_translation(1, 1, 1), None);
        assert_eq!(snapshot.after_fault_snapshot(), None);
    }

    #[test]
    fn constructor_failure_after_any_successful_prefix_prevents_commit() {
        let hooks = InitPublicationPhase::PrivateReady
            .after_dma_hooks()
            .unwrap();
        for discovered in 1..=8 {
            for constructed in 0..discovered {
                // Even enabling every retained unit cannot hide a rejected DRHD.
                let ready = hooks
                    .after_translation(discovered, constructed, constructed)
                    .and_then(InitPublicationPhase::after_fault_snapshot);
                assert!(ready.is_none());
            }
        }
    }

    #[test]
    fn translation_failure_after_any_successful_prefix_prevents_commit() {
        let hooks = InitPublicationPhase::PrivateReady
            .after_dma_hooks()
            .unwrap();
        for discovered in 1..=8 {
            for translated in 0..discovered {
                let ready = hooks
                    .after_translation(discovered, discovered, translated)
                    .and_then(InitPublicationPhase::after_fault_snapshot);
                assert!(ready.is_none());
            }
        }
    }

    #[test]
    fn empty_or_inconsistent_unit_sets_prevent_commit() {
        let hooks = InitPublicationPhase::PrivateReady
            .after_dma_hooks()
            .unwrap();
        for (discovered, constructed, translated) in [(0, 0, 0), (2, 3, 2), (2, 2, 3)] {
            assert_eq!(
                hooks.after_translation(discovered, constructed, translated),
                None
            );
        }
    }
}
