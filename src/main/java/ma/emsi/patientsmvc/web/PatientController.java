package ma.emsi.patientsmvc.web;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.ui.Model;
import lombok.AllArgsConstructor;
import ma.emsi.patientsmvc.entities.Patient;
import ma.emsi.patientsmvc.repositories.PatientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@AllArgsConstructor

public class PatientController {

    private PatientRepository patientRepository;



    @GetMapping(path="/user/index")
    public String patients(Model model,
                           @RequestParam(name="page",defaultValue ="0") int page,
                           @RequestParam(name="size",defaultValue ="5") int size,
                           @RequestParam(name="keyword", defaultValue ="") String keyword)
                            {
        Page<Patient> pagePatients = patientRepository.findByNomContains(keyword,PageRequest.of(page,size));
        model.addAttribute("listPatient",pagePatients.getContent());
        model.addAttribute("pages",new int[pagePatients.getTotalPages()]);
        model.addAttribute("currentPage",page);
        model.addAttribute("keyword",keyword);
        return "patients";
    }
    @GetMapping("/admin/delete")
    public String delete(Long id, String keyword, int page) {
        patientRepository.deleteById(id);
        return "redirect:/index?page="+page+"&keyword="+keyword;
    }



    @GetMapping(path = "/")
    public String home(){
        return "redirect:/user/index";
    }

    @GetMapping("/patients")
    @ResponseBody
    public List<Patient> listPatients(){
        return patientRepository.findAll();
    }

    @GetMapping("/admin/formPatients")
    public String formPatients(Model model){
        model.addAttribute("patient", new Patient());
        return "formPatients";
    }

    @PostMapping(path = "/admin/save")
    public String save(Model model, @Valid Patient patient,BindingResult bindingResult,
                       @RequestParam(defaultValue = "0") int page,
                       @RequestParam(defaultValue = "0") String keyword){
        if(bindingResult.hasErrors()) return "formPatients";
        patientRepository.save(patient);
        return "redirect:/index?page="+page+"&keyword="+keyword;
    }

    @GetMapping("/admin/editPatient")
    public String editPatient(Model model, Long id, String keyword, int page){
        Patient patient = patientRepository.findById(id).orElse(null);
        if(patient==null) throw new RuntimeException("Patient introuvable");
        model.addAttribute("patient", patient);
        model.addAttribute("page",page);
        model.addAttribute("keyword",keyword);
        return "editPatient";
    }
}



