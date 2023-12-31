package ma.emsi.patientsmvc.repositories;

import ma.emsi.patientsmvc.entities.Patient;
import org.springframework.boot.autoconfigure.jackson.JacksonProperties;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PatientRepository extends JpaRepository<Patient, Long> {
    Page<Patient> findByNomContains(String kw, Pageable pageable);
}
