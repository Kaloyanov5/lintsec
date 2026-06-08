package com.lintsec.service;

import com.lintsec.domain.Scan;
import com.lintsec.domain.ScanStatus;
import com.lintsec.exception.ConflictException;
import com.lintsec.exception.NotFoundException;
import com.lintsec.repository.ScanRepository;
import com.lintsec.repository.FindingRepository;
import com.lintsec.repository.ScanPageRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScanServiceTest {

    @Mock ScanRepository scanRepository;
    @Mock ScanCancellationRegistry cancellationRegistry;
    @Mock FindingRepository findingRepository;
    @Mock ScanPageRepository scanPageRepository;
    @InjectMocks ScanService scanService;

    private static Scan scanWithStatus(Long id, ScanStatus status) {
        Scan scan = new Scan();
        scan.setStatus(status);
        scan.setId(id);
        return scan;
    }

    @Test
    void cancelRunningScanFlagsAndRequests() {
        Scan scan = scanWithStatus(7L, ScanStatus.RUNNING);
        when(scanRepository.findByIdAndUserId(7L, 1L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        Scan result = scanService.cancelScan(1L, 7L);

        assertTrue(result.isCancelRequested());
        verify(cancellationRegistry).request(7L);
        verify(scanRepository).save(scan);
    }

    @Test
    void cancelPendingScanFlagsAndRequests() {
        Scan scan = scanWithStatus(8L, ScanStatus.PENDING);
        when(scanRepository.findByIdAndUserId(8L, 1L)).thenReturn(Optional.of(scan));
        when(scanRepository.save(any(Scan.class))).thenAnswer(inv -> inv.getArgument(0));

        Scan result = scanService.cancelScan(1L, 8L);

        assertTrue(result.isCancelRequested());
        verify(cancellationRegistry).request(8L);
    }

    @Test
    void cancelCompletedScanIsConflict() {
        Scan scan = scanWithStatus(9L, ScanStatus.COMPLETE);
        when(scanRepository.findByIdAndUserId(9L, 1L)).thenReturn(Optional.of(scan));

        assertThrows(ConflictException.class, () -> scanService.cancelScan(1L, 9L));
        verify(cancellationRegistry, never()).request(any());
    }

    @Test
    void cancelMissingScanIsNotFound() {
        when(scanRepository.findByIdAndUserId(99L, 1L)).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> scanService.cancelScan(1L, 99L));
    }

    @Test
    void deleteTerminalScanCascades() {
        Scan scan = scanWithStatus(11L, ScanStatus.COMPLETE);
        when(scanRepository.findByIdAndUserId(11L, 1L)).thenReturn(Optional.of(scan));

        scanService.deleteScan(1L, 11L);

        InOrder order = inOrder(findingRepository, scanPageRepository, scanRepository);
        order.verify(findingRepository).deleteByScanId(11L);
        order.verify(scanPageRepository).deleteByScanId(11L);
        order.verify(scanRepository).delete(scan);
    }

    @Test
    void deleteRunningScanIsConflict() {
        Scan scan = scanWithStatus(12L, ScanStatus.RUNNING);
        when(scanRepository.findByIdAndUserId(12L, 1L)).thenReturn(Optional.of(scan));

        assertThrows(ConflictException.class, () -> scanService.deleteScan(1L, 12L));
        verify(scanRepository, never()).delete(any());
    }
}
